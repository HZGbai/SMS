/**
 * 短信转发系统 —— Cloudflare Worker 单文件实现
 *
 * 职责只有三件事：
 *   1. 自身鉴权（ADMIN 密码）
 *   2. KV 读写（绑定名 kv，超限清理最旧，每条带时间戳）
 *   3. 极简网页（刷新 + 短信列表）
 *
 * 路由布局 —— **所有接口都挂在 /api/ 下面**，根路径只留网页：
 *
 *   GET  /             网页（无数据，不校验密码）
 *   GET  /api/health   健康检查（无数据，不校验密码）
 *   POST /api/sms      写入短信
 *   GET  /api/sms      读取列表
 *
 * 接口统一挂 /api/ 是为了让 WAF 里一条 `URI Path starts with /api/` 的 Skip 规则
 * 就能覆盖全部接口 —— 托管挑战需要执行 JS，安卓 App 天然过不去，必须整体跳过。
 *
 * 访问控制分两层，各管一段，互不依赖：
 *
 *   ① 边缘 WAF 规则 —— 只放行携带约定字段（形如 `access_<32位>`）的请求。
 *      挡的是扫描器和刷量，保护 Workers 免费额度。请求头或查询参数带都算数。
 *      本文件不参与校验（被拦的请求根本到不了这里）。
 *   ② Worker 自身 —— 校验 ADMIN 密码，请求头 X-Admin-Password / AccessToken /
 *      `Authorization: Bearer` 三选一。这是最后一道闸：即使 WAF 规则被绕过，
 *      没有密码也读不到、写不进任何数据。
 *
 * KV 数据布局：
 *   sms:index            -> JSON 数组，按时间升序保存记录 id（最旧在前）
 *   sms:rec:<id>         -> JSON 单条记录
 *   sms:cid:<clientId>   -> 记录 id，用于幂等去重（带 TTL）
 *
 * id 形如 `000001758200000000-3f9a2c`：前 18 位是补零的毫秒时间戳，
 * 因此 key 的字典序 == 时间序。
 */

// ---------------------------------------------------------------- 配置

const MAX_BATCH = 500; // 单次请求最多接收多少条
const DEFAULT_MAX_RECORDS = 200; // 未配置 MAX_RECORDS 时的默认上限
const LIST_PAGE = 1000; // KV list 分页大小

const INDEX_KEY = "sms:index";
const REC_PREFIX = "sms:rec:";
const CID_PREFIX = "sms:cid:";
const DEDUP_TTL = 60 * 60 * 24 * 7; // 幂等键保留 7 天

const ICON_URL = "https://hzgbai.dpdns.org/icon/mainicon.png";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,X-Admin-Password,AccessToken,Authorization",
  "Access-Control-Max-Age": "86400",
};

// ---------------------------------------------------------------- 鉴权

/** 定长比较，避免早退泄露长度/前缀信息。 */
function safeEqual(a, b) {
  const x = new TextEncoder().encode(String(a ?? ""));
  const y = new TextEncoder().encode(String(b ?? ""));
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x[i] ^ y[i];
  return diff === 0;
}

/**
 * 从请求里取 ADMIN 密码，三种写法任选其一：
 *   X-Admin-Password: <密码>     —— 安卓客户端与网页用
 *   AccessToken: <密码>          —— 兼容只认这个名字的调用方
 *   Authorization: Bearer <密码> —— 标准写法，curl / 脚本方便
 */
function extractAdminCredential(request) {
  const header = request.headers.get("X-Admin-Password");
  if (header) return header;

  const accessToken = request.headers.get("AccessToken");
  if (accessToken) return accessToken;

  const auth = request.headers.get("Authorization") || "";
  if (/^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, "").trim();

  return "";
}

/** 返回 { ok, status, reason }。 */
function checkAdmin(request, env) {
  const expected = env.ADMIN;
  if (!expected) {
    return { ok: false, status: 500, reason: "服务端未配置 ADMIN 变量" };
  }
  const provided = extractAdminCredential(request);
  if (!provided) {
    return { ok: false, status: 401, reason: "缺少 X-Admin-Password / AccessToken 请求头" };
  }
  if (!safeEqual(provided, expected)) {
    return { ok: false, status: 403, reason: "密码错误" };
  }
  return { ok: true };
}

// ---------------------------------------------------------------- KV 存储

function pad(n, len) {
  return String(n).padStart(len, "0");
}

function randomSuffix() {
  const bytes = new Uint8Array(3);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function buildId(ts) {
  return `${pad(ts, 18)}-${randomSuffix()}`;
}

function normalizeMax(value) {
  const n = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_MAX_RECORDS;
  return Math.min(n, 5000);
}

class SmsStore {
  constructor(kv, maxRecords) {
    this.kv = kv;
    this.max = normalizeMax(maxRecords);
  }

  async readIndex() {
    const raw = await this.kv.get(INDEX_KEY, "json");
    if (!Array.isArray(raw)) return [];
    return raw.filter((id) => typeof id === "string" && id.length > 0);
  }

  /**
   * 追加一条记录。返回 { record, duplicate, evicted }。
   * clientId 命中去重表时直接返回已存在的记录，不重复写入。
   */
  async append(input) {
    const ts = Number.isFinite(input.ts) ? input.ts : Date.now();
    const clientId = typeof input.clientId === "string" ? input.clientId.trim() : "";

    if (clientId) {
      const existingId = await this.kv.get(CID_PREFIX + clientId);
      if (existingId) {
        const existing = await this.kv.get(REC_PREFIX + existingId, "json");
        if (existing) return { record: existing, duplicate: true, evicted: [] };
      }
    }

    const record = {
      id: buildId(ts),
      ts,
      receivedAt: new Date(ts).toISOString(),
      from: String(input.from ?? "").slice(0, 128),
      content: String(input.content ?? "").slice(0, 8000),
      device: String(input.device ?? "").slice(0, 128),
      deviceTs: Number.isFinite(input.deviceTs) ? input.deviceTs : null,
      clientId: clientId || null,
    };

    await this.kv.put(REC_PREFIX + record.id, JSON.stringify(record));

    if (clientId) {
      await this.kv.put(CID_PREFIX + clientId, record.id, { expirationTtl: DEDUP_TTL });
    }

    const evicted = await this.#indexAppend(record.id);

    return { record, duplicate: false, evicted };
  }

  /**
   * 把 id 写进索引；超出 max 时从头部（最旧）裁掉并删除对应记录。
   *
   * KV 没有原子操作，高并发下 read-modify-write 可能互相覆盖。
   * 这里的做法是写完后回读校验，最多重试 5 次；短信转发这种量级足够。
   * 真正丢索引也能靠 rebuildIndex() 从 sms:rec: 前缀自愈。
   */
  async #indexAppend(id) {
    let evicted = [];

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const index = await this.readIndex();
      if (!index.includes(id)) {
        index.push(id);
        evicted = [];
        while (index.length > this.max) {
          const oldest = index.shift();
          if (oldest) evicted.push(oldest);
        }
        await this.kv.put(INDEX_KEY, JSON.stringify(index));
        if (evicted.length > 0) {
          await Promise.all(evicted.map((oldId) => this.kv.delete(REC_PREFIX + oldId)));
        }
      }

      const check = await this.readIndex();
      if (check.includes(id)) return evicted;

      await new Promise((r) => setTimeout(r, 40 * (attempt + 1)));
    }

    return evicted;
  }

  /** 读取记录，新的在前。顺手跳过索引里已被删除的悬空 id。 */
  async list({ limit = 100, since = 0 } = {}) {
    let index = await this.readIndex();
    if (index.length === 0) index = await this.rebuildIndex();

    const ids = index.slice().reverse();
    const picked = [];
    for (const id of ids) {
      const rec = await this.kv.get(REC_PREFIX + id, "json");
      if (!rec) continue;
      if (since && Number(rec.ts) <= since) continue;
      picked.push(rec);
      if (picked.length >= limit) break;
    }
    return picked;
  }

  /** 索引丢失/损坏时，从 sms:rec: 前缀重建。 */
  async rebuildIndex() {
    const ids = [];
    let cursor;
    do {
      const page = await this.kv.list({ prefix: REC_PREFIX, cursor, limit: LIST_PAGE });
      for (const key of page.keys) ids.push(key.name.slice(REC_PREFIX.length));
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);

    ids.sort(); // id 前缀是补零时间戳，字典序即时间序
    const trimmed = ids.slice(-this.max);
    await this.kv.put(INDEX_KEY, JSON.stringify(trimmed));
    return trimmed;
  }
}

// ---------------------------------------------------------------- 网页

const PAGE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>短信</title>
<link rel="icon" type="image/png" href="${ICON_URL}">
<link rel="apple-touch-icon" href="${ICON_URL}">
<meta name="theme-color" content="#1f6feb">
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0; padding: 12px; }
  header { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
  #logo { width: 28px; height: 28px; border-radius: 6px; flex: 0 0 auto; }
  input, button { font: inherit; padding: 6px 8px; }
  input[type=password] { flex: 1 1 180px; min-width: 120px; }
  #acc { width: 100%; box-sizing: border-box; margin-bottom: 8px; font-size: 12px; }
  #status { margin-bottom: 12px; font-size: 12px; opacity: .7; }
  #list { display: flex; flex-direction: column; gap: 8px; }
  .item { border: 1px solid rgba(128,128,128,.4); border-radius: 6px; padding: 8px 10px; }
  .meta { display: flex; justify-content: space-between; gap: 8px; font-size: 12px; opacity: .7; margin-bottom: 4px; }
  .from { font-weight: 600; opacity: .9; }
  .body { white-space: pre-wrap; word-break: break-word; }
  .empty { padding: 16px; text-align: center; opacity: .6; }
</style>
</head>
<body>
<header>
  <img id="logo" src="${ICON_URL}" alt="">
  <input id="pwd" type="password" placeholder="ADMIN 密码" autocomplete="current-password">
  <button id="refresh">刷新</button>
  <label><input id="auto" type="checkbox"> 自动刷新</label>
</header>
<input id="acc" placeholder="access_… （WAF 白名单字段，可从地址栏自动带出）" autocomplete="off">
<div id="status">未加载</div>
<div id="list"></div>

<script>
(function () {
  var pwd = document.getElementById('pwd');
  var acc = document.getElementById('acc');
  var status = document.getElementById('status');
  var list = document.getElementById('list');
  var auto = document.getElementById('auto');
  var logo = document.getElementById('logo');
  var timer = null;
  var KEY = 'sms_admin_pwd';
  var ACC_KEY = 'sms_access_field';

  // 图标加载失败就把占位图藏掉，别显示一个破图
  logo.addEventListener('error', function () { logo.style.display = 'none'; });

  pwd.value = localStorage.getItem(KEY) || '';

  // WAF 白名单字段：优先从地址栏 ?access_xxx=1 取，其次取上次填过的。
  // 从地址栏取到时顺手种个 cookie —— 以后直接访问 / 也能过 WAF，不必带参数。
  function detectAccessField() {
    var found = '';
    try {
      new URLSearchParams(location.search).forEach(function (v, k) {
        if (!found && k.indexOf('access_') === 0) found = k;
      });
    } catch (e) { /* 老浏览器没有 URLSearchParams，忽略 */ }

    if (found) {
      try { localStorage.setItem(ACC_KEY, found); } catch (e) {}
      document.cookie = found + '=1; path=/; max-age=31536000; SameSite=Lax';
      return found;
    }
    try { return localStorage.getItem(ACC_KEY) || ''; } catch (e) { return ''; }
  }

  acc.value = detectAccessField();

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fmt(ts) {
    if (!ts) return '-';
    return new Date(ts).toLocaleString();
  }

  function render(items) {
    if (!items.length) {
      list.innerHTML = '<div class="empty">暂无短信</div>';
      return;
    }
    list.innerHTML = items.map(function (m) {
      return '<div class="item">' +
        '<div class="meta"><span class="from">' + esc(m.from || '(未知)') + '</span>' +
        '<span>' + esc(fmt(m.ts)) + (m.device ? ' · ' + esc(m.device) : '') + '</span></div>' +
        '<div class="body">' + esc(m.content) + '</div>' +
        '</div>';
    }).join('');
  }

  async function load() {
    var p = pwd.value.trim();
    var field = acc.value.trim();
    if (!p) {
      status.textContent = '请输入 ADMIN 密码';
      return;
    }
    status.textContent = '加载中…';

    // WAF 白名单字段两种带法都上：查询参数 + 自定义请求头。
    // 规则写成哪种都能命中，不用来回试。
    var url = '/api/sms?limit=200';
    var headers = { 'X-Admin-Password': p };
    if (field) {
      url += '&' + encodeURIComponent(field) + '=1';
      headers[field] = '1';
    }

    try {
      var res = await fetch(url, { headers: headers });
      var raw = await res.text();
      var data = {};
      try { data = JSON.parse(raw); } catch (e) { /* 非 JSON，多半是拦截页 */ }
      if (!res.ok) {
        var hint = '';
        if (res.status === 403) {
          var mit = (res.headers.get('cf-mitigated') || '').toLowerCase();
          if (mit === 'challenge' || raw.indexOf('Just a moment') >= 0) {
            hint = ' · 被 Cloudflare 托管挑战拦住（跟 access_ 字段无关，需要浏览器执行 JS，' +
              '给 /api/* 加一条 Skip 规则即可）';
          } else if (!data.error) {
            hint = ' · 被 WAF 拦了，核对上面那行 access_ 字段';
          }
        }
        status.textContent = '失败 (' + res.status + '): ' + (data.error || res.statusText) + hint;
        if (res.status === 401 || res.status === 403) list.innerHTML = '';
        return;
      }
      localStorage.setItem(KEY, p);
      if (field) { try { localStorage.setItem(ACC_KEY, field); } catch (e) {} }
      render(data.messages || []);
      status.textContent = '共 ' + (data.count || 0) + ' 条 / 上限 ' + (data.max || '-') +
        ' · 更新于 ' + new Date().toLocaleTimeString();
    } catch (e) {
      status.textContent = '请求异常: ' + e.message;
    }
  }

  document.getElementById('refresh').addEventListener('click', load);
  pwd.addEventListener('keydown', function (e) { if (e.key === 'Enter') load(); });
  acc.addEventListener('keydown', function (e) { if (e.key === 'Enter') load(); });
  acc.addEventListener('change', function () {
    var v = acc.value.trim();
    try {
      if (v) localStorage.setItem(ACC_KEY, v);
      else localStorage.removeItem(ACC_KEY);
    } catch (e) {}
  });
  auto.addEventListener('change', function () {
    if (timer) { clearInterval(timer); timer = null; }
    if (auto.checked) { load(); timer = setInterval(load, 15000); }
  });

  if (pwd.value) load();
})();
</script>
</body>
</html>
`;

// ---------------------------------------------------------------- 路由

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS },
  });
}

function text(body, status = 200, contentType = "text/plain; charset=utf-8") {
  return new Response(body, { status, headers: { "Content-Type": contentType, ...CORS_HEADERS } });
}

function getStore(env) {
  if (!env.kv) throw new Error("缺少 kv 绑定，请检查 wrangler.toml");
  return new SmsStore(env.kv, normalizeMax(env.MAX_RECORDS));
}

/** 兼容客户端可能用的多种字段名。 */
function normalizeOne(raw) {
  if (!raw || typeof raw !== "object") return null;
  const from = String(raw.from ?? raw.address ?? raw.sender ?? "").trim();
  const content = String(raw.content ?? raw.body ?? raw.message ?? "").trim();
  if (!from && !content) return null;

  const deviceTs = Number(raw.deviceTs ?? raw.date ?? raw.timestamp);
  return {
    from: from || "(未知)",
    content,
    device: raw.device ?? "",
    deviceTs: Number.isFinite(deviceTs) && deviceTs > 0 ? deviceTs : null,
    clientId: raw.clientId ?? raw.id ?? "",
    ts: Date.now(),
  };
}

/** POST /api/sms —— 接收短信，单条或批量 */
async function handleIngest(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "请求体不是合法 JSON" }, 400);
  }

  const rawList = Array.isArray(body) ? body : Array.isArray(body?.messages) ? body.messages : [body];
  if (rawList.length === 0) return json({ ok: false, error: "没有可写入的记录" }, 400);
  if (rawList.length > MAX_BATCH) {
    return json({ ok: false, error: `单次最多 ${MAX_BATCH} 条，当前 ${rawList.length} 条` }, 413);
  }

  const store = getStore(env);
  const results = [];
  let accepted = 0;
  let duplicates = 0;
  let evictedTotal = 0;

  for (const raw of rawList) {
    const item = normalizeOne(raw);
    if (!item) {
      results.push({ ok: false, error: "缺少发件人或内容" });
      continue;
    }
    try {
      const { record, duplicate, evicted } = await store.append(item);
      if (duplicate) duplicates += 1;
      else {
        accepted += 1;
        evictedTotal += evicted?.length || 0;
      }
      results.push({ ok: true, id: record.id, duplicate: Boolean(duplicate) });
    } catch (err) {
      results.push({ ok: false, error: err.message });
    }
  }

  const failed = results.filter((r) => !r.ok).length;
  const payload = {
    ok: failed === 0,
    accepted,
    duplicates,
    failed,
    evicted: evictedTotal,
    results: results.length === 1 ? results[0] : results,
  };

  return json(payload, failed === 0 ? 200 : failed === results.length ? 400 : 207);
}

/** GET /api/sms —— 列出短信，新的在前 */
async function handleList(url, env) {
  const limitRaw = Number.parseInt(url.searchParams.get("limit") ?? "100", 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 100;
  const since = Number.parseInt(url.searchParams.get("since") ?? "0", 10) || 0;

  const store = getStore(env);
  const messages = await store.list({ limit, since });
  return json({ ok: true, count: messages.length, max: store.max, messages });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      // ── 网页本体（不是接口，保留在根路径）────────────────────────────
      // 页面里没有任何数据，所以不校验 ADMIN 密码。
      if (path === "/" || path === "/index.html") {
        if (request.method !== "GET") return text("Method Not Allowed", 405);
        return text(PAGE_HTML, 200, "text/html; charset=utf-8");
      }

      // ── 所有接口一律挂在 /api/ 下面 ───────────────────────────────────
      // 这样 WAF 里只需要写一条 `URI Path starts with /api/` 的 Skip 规则，
      // 就能让全部接口跳过托管挑战（挑战要执行 JS，安卓 App 过不去）。
      if (!path.startsWith("/api/")) {
        return json({ ok: false, error: `未知路由 ${request.method} ${path}` }, 404);
      }

      // GET /api/health —— 健康检查，给客户端「测试连接」用。
      // 不返回任何数据，所以不校验密码。
      if (path === "/api/health") {
        if (request.method !== "GET") return json({ ok: false, error: "Method Not Allowed" }, 405);
        return json({
          ok: true,
          service: "sms-forwarder",
          kv: Boolean(env.kv),
          maxRecords: normalizeMax(env.MAX_RECORDS),
        });
      }

      // ── 以下全部需要 ADMIN 密码 ──────────────────────────────────────
      const auth = checkAdmin(request, env);
      if (!auth.ok) {
        return json({ ok: false, error: auth.reason }, auth.status);
      }

      if (path === "/api/sms") {
        if (request.method === "POST") return await handleIngest(request, env);
        if (request.method === "GET") return await handleList(url, env);
        return json({ ok: false, error: "Method Not Allowed" }, 405);
      }

      return json({ ok: false, error: `未知路由 ${request.method} ${path}` }, 404);
    } catch (err) {
      return json({ ok: false, error: err.message || String(err) }, 500);
    }
  },
};
