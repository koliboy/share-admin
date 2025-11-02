export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      return new Response("Server error: " + (err?.stack || err), { status: 500 });
    }
  }
};

// ----------------- CONFIG -----------------
const ALLOWED_HOSTS = new Set(["admin.linkfile.io"]);

// RBAC roles
const PERMS = {
  admin:     ['users.read','users.write','reports.read','reports.write','files.read','files.write','analytics.read'],
  moderator: ['reports.read','reports.write','files.read'],
  analyst:   ['analytics.read','files.read','reports.read']
};

const SESSION_COOKIE = "lf_admin";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

// ----------------- REQUEST ROUTER -----------------
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const host = request.headers.get("host") || "";

  // Strict host pin
  if (!ALLOWED_HOSTS.has(host)) {
    return new Response("Forbidden (host)", { status: 403 });
  }

  // Static assets path (optional)
  if (url.pathname.startsWith("/assets/")) {
    return new Response("Not found", { status: 404 });
  }

  // session read
  const cookies = parseCookies(request.headers.get("Cookie"));
  const session = await readSession(env, cookies[SESSION_COOKIE]);

  // setup/migrations
  if (url.pathname === "/admin/setup") {
    const token = url.searchParams.get("token");
    if (token !== env.ADMIN_SETUP_TOKEN) return new Response("Forbidden", { status: 403 });
    await runMigrations(env);
    // seed only if empty
    const exists = await env.DB.prepare(`SELECT COUNT(*) as c FROM admin_users`).first();
    if (!exists || !exists.c) {
      const email = url.searchParams.get("email") || "admin@linkfile.io";
      const name  = url.searchParams.get("name")  || "Administrator";
      const pass  = url.searchParams.get("pass")  || "ChangeMe!2025";
      await seedFirstAdmin(env, email, name, pass);
      return html(`<pre>Setup complete.\nAdmin: ${email}\nPassword: ${pass}\n</pre>`);
    }
    return html(`<pre>Migrations complete. Admin already exists.</pre>`);
  }

  // auth routes
  if (url.pathname === "/admin/login" && request.method === "GET") {
    return adminLoginPage();
  }
  if (url.pathname === "/admin/login" && request.method === "POST") {
    const fd = await request.formData();
    const email = (fd.get("email")||"").toString().trim().toLowerCase();
    const password = (fd.get("password")||"").toString();
    const u = await env.DB.prepare(`SELECT * FROM admin_users WHERE email=? LIMIT 1`).bind(email).first();
    if (!u) return adminLoginPage("Invalid credentials");
    const ok = await pbkdf2Verify(password, u.pass_salt, u.pass_hash, u.pass_iters||120000);
    if (!ok) return adminLoginPage("Invalid credentials");
    const { cookie } = await createSession(env, u.id, u.role);
    const headers = new Headers({ Location: "/admin" });
    headers.append("Set-Cookie", `${SESSION_COOKIE}=${cookie}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`);
    return new Response("", { status: 302, headers });
  }
  if (url.pathname === "/admin/logout") {
    const ck = cookies[SESSION_COOKIE];
    await destroySession(env, ck);
    const headers = new Headers({ Location: "/admin/login" });
    headers.append("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
    return new Response("", { status: 302, headers });
  }

  // everything below requires session
  if (!session) {
    return new Response("", { status: 302, headers: { Location: "/admin/login" } });
  }

  // dashboard
  if (url.pathname === "/admin") {
    const files = await env.DB.prepare(`SELECT COUNT(*) as c FROM files`).first();
    const reportsOpen = await env.DB.prepare(`SELECT COUNT(*) as c FROM reports WHERE status='open'`).first();
    const now = Math.floor(Date.now()/1000);
    const week = now - 7*86400;
    const dl7 = await env.DB.prepare(`SELECT COUNT(*) as c FROM file_events WHERE created_at>=? AND event_type='download'`).bind(week).first();
    const st7 = await env.DB.prepare(`SELECT COUNT(*) as c FROM file_events WHERE created_at>=? AND event_type='stream'`).bind(week).first();
    return adminDashPage({
      files: files?.c || 0,
      reports_open: reportsOpen?.c || 0,
      dl_7d: dl7?.c || 0,
      stream_7d: st7?.c || 0
    }, session);
  }

  // reports list
  if (url.pathname === "/admin/reports" && request.method === "GET") {
    const guard = guardPerm(session, "reports.read");
    if (!guard.ok) return new Response("Forbidden", { status: 403 });
    const rows = await env.DB.prepare(`SELECT * FROM reports ORDER BY id DESC LIMIT 500`).all();
    return adminReportsPage(rows?.results || [], session);
  }
  // resolve
  let m;
  if ((m = url.pathname.match(/^\/admin\/reports\/(\d+)\/resolve$/)) && request.method === "POST") {
    const guard = guardPerm(session, "reports.write");
    if (!guard.ok) return new Response("Forbidden", { status: 403 });
    const id = +m[1];
    const now = Math.floor(Date.now()/1000);
    await env.DB.prepare(`UPDATE reports SET status='resolved', resolver_user_id=?, resolved_at=? WHERE id=?`)
      .bind(session.user_id, now, id).run();
    return redirect("/admin/reports");
  }
  if ((m = url.pathname.match(/^\/admin\/reports\/(\d+)\/reopen$/)) && request.method === "POST") {
    const guard = guardPerm(session, "reports.write");
    if (!guard.ok) return new Response("Forbidden", { status: 403 });
    const id = +m[1];
    await env.DB.prepare(`UPDATE reports SET status='open', resolver_user_id=NULL, resolved_at=NULL WHERE id=?`).bind(id).run();
    return redirect("/admin/reports");
  }

  // files search/list
  if (url.pathname === "/admin/files" && request.method === "GET") {
    const guard = guardPerm(session, "files.read");
    if (!guard.ok) return new Response("Forbidden", { status: 403 });
    const q = (url.searchParams.get("q")||"").trim();
    let rows = [];
    if (q) {
      if (/^[0-9A-Za-z]+$/.test(q)) {
        rows = (await env.DB.prepare(`SELECT * FROM files WHERE short_id=? OR name LIKE ? ORDER BY id DESC LIMIT 200`)
          .bind(q, `%${q}%`).all()).results;
      } else {
        rows = (await env.DB.prepare(`SELECT * FROM files WHERE name LIKE ? ORDER BY id DESC LIMIT 200`)
          .bind(`%${q}%`).all()).results;
      }
    } else {
      rows = (await env.DB.prepare(`SELECT * FROM files ORDER BY id DESC LIMIT 200`).all()).results;
    }
    return adminFilesListPage(q, rows || [], session);
  }

  // users
  if (url.pathname === "/admin/users" && request.method === "GET") {
    const guard = guardPerm(session, "users.read");
    if (!guard.ok) return new Response("Forbidden", { status: 403 });
    const users = (await env.DB.prepare(`SELECT id,email,name,role,created_at FROM admin_users ORDER BY id DESC`).all()).results || [];
    return adminUsersPage(users, session);
  }
  if (url.pathname === "/admin/users/create" && request.method === "POST") {
    const guard = guardPerm(session, "users.write");
    if (!guard.ok) return new Response("Forbidden", { status: 403 });
    const fd = await request.formData();
    const email = (fd.get("email")||"").toString().trim().toLowerCase();
    const name  = (fd.get("name")||"").toString().trim();
    const role  = (fd.get("role")||"moderator").toString();
    const pass  = (fd.get("password")||"").toString();
    if (!email || !pass) return new Response("Missing", { status: 400 });
    const now = Math.floor(Date.now()/1000);
    const { saltHex, hashHex, iter } = await pbkdf2Hash(pass);
    await env.DB.prepare(`INSERT INTO admin_users (email,name,role,pass_salt,pass_hash,pass_iters,created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(email, name, role, saltHex, hashHex, iter, now).run();
    return redirect("/admin/users");
  }
  if ((m = url.pathname.match(/^\/admin\/users\/(\d+)\/delete$/)) && request.method === "POST") {
    const guard = guardPerm(session, "users.write");
    if (!guard.ok) return new Response("Forbidden", { status: 403 });
    const id = +m[1];
    await env.DB.prepare(`DELETE FROM admin_users WHERE id=?`).bind(id).run();
    return redirect("/admin/users");
  }

  return new Response("Not found", { status: 404 });
}

// ----------------- MIGRATIONS -----------------
async function runMigrations(env) {
  const stmts = [
`CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  role TEXT NOT NULL DEFAULT 'admin',
  pass_salt TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  pass_iters INTEGER NOT NULL DEFAULT 120000,
  created_at INTEGER NOT NULL
);`,
`CREATE TABLE IF NOT EXISTS admin_sessions (
  sid TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);`,
`CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_short_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  message TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  resolver_user_id INTEGER,
  resolved_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);`,
`CREATE TABLE IF NOT EXISTS file_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL,
  short_id TEXT,
  event_type TEXT NOT NULL,
  ip TEXT,
  ua TEXT,
  created_at INTEGER NOT NULL
);`
  ];
  for (const s of stmts) await env.DB.prepare(s).run();
}

async function seedFirstAdmin(env, email, name, password) {
  const now = Math.floor(Date.now()/1000);
  const { saltHex, hashHex, iter } = await pbkdf2Hash(password);
  await env.DB.prepare(`INSERT INTO admin_users (email,name,role,pass_salt,pass_hash,pass_iters,created_at)
    VALUES (?, ?, 'admin', ?, ?, ?, ?)`).bind(email, name, saltHex, hashHex, iter, now).run();
}

// ----------------- AUTH / SESSIONS -----------------
async function createSession(env, userId, role) {
  const now = Math.floor(Date.now()/1000);
  const sid = crypto.randomUUID().replace(/-/g,'');
  const exp = now + SESSION_TTL_SECONDS;
  await env.DB.prepare(`INSERT INTO admin_sessions (sid, user_id, role, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?)`).bind(sid, userId, role, now, exp).run();
  const sig = await hmacHex(env.SESSION_HMAC_SECRET, sid);
  return { cookie: `${sid}.${sig}`, exp };
}
async function readSession(env, cookieValue) {
  if (!cookieValue) return null;
  const [sid, sig] = cookieValue.split(".");
  if (!sid || !sig) return null;
  const expect = await hmacHex(env.SESSION_HMAC_SECRET, sid);
  if (!safeEqual(sig, expect)) return null;
  const row = await env.DB.prepare(`SELECT s.sid, s.user_id, s.role, s.expires_at, u.email, u.name
    FROM admin_sessions s JOIN admin_users u ON u.id=s.user_id WHERE s.sid=? LIMIT 1`).bind(sid).first();
  if (!row) return null;
  const now = Math.floor(Date.now()/1000);
  if (row.expires_at < now) return null;
  return row; // {sid,user_id,role,expires_at,email,name}
}
async function destroySession(env, cookieValue) {
  if (!cookieValue) return;
  const sid = cookieValue.split(".")[0];
  if (!sid) return;
  await env.DB.prepare(`DELETE FROM admin_sessions WHERE sid=?`).bind(sid).run();
}
function guardPerm(session, perm) {
  if (!session) return { ok:false };
  if (!perm) return { ok:true };
  const list = PERMS[session.role] || [];
  if (session.role === "admin" || list.includes(perm)) return { ok:true };
  return { ok:false };
}

// ----------------- CRYPTO -----------------
async function pbkdf2Hash(password, saltHex, iterations = 120000, keyLen = 32) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", hash:"SHA-256", salt, iterations }, keyMaterial, keyLen*8);
  const dk = new Uint8Array(bits);
  return { saltHex: bufToHex(salt), hashHex: bufToHex(dk), iter: iterations };
}
async function pbkdf2Verify(password, saltHex, hashHex, iterations=120000) {
  const { hashHex: h2 } = await pbkdf2Hash(password, saltHex, iterations, hashHex.length/2);
  return safeEqual(hashHex, h2);
}
async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return bufToHex(sig);
}
function safeEqual(a,b){ if(a.length!==b.length)return false; let r=0; for(let i=0;i<a.length;i++) r|=a.charCodeAt(i)^b.charCodeAt(i); return r===0; }
function bufToHex(buf){ return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join(""); }
function hexToBuf(hex){ const out=new Uint8Array(hex.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(hex.substr(i*2,2),16); return out; }

// ----------------- HTML HELPERS -----------------
function redirect(to){ return new Response("", { status:302, headers:{ Location: to } }); }
function html(s){ return new Response(s, { headers: { "content-type":"text/html; charset=utf-8" } }); }
function htmlEscape(s){ return (s??"").toString().replace(/[&<>"']/g, m=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[m])); }
function bytesPretty(n){ if(!n||n<=0) return "0 B"; const u=["B","KB","MB","GB","TB","PB"]; const e=Math.floor(Math.log(n)/Math.log(1024)); return (n/Math.pow(1024,e)).toFixed(2)+" "+u[e]; }
function parseCookies(h){ const out={}; if(!h) return out; h.split(/; */).forEach(p=>{ const i=p.indexOf("="); if(i>0) out[decodeURIComponent(p.slice(0,i).trim())]=decodeURIComponent(p.slice(i+1).trim()); }); return out; }

function shell(title, body, session, opts={}) {
  return html(`<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${htmlEscape(title)}</title>
  <link rel="icon" href="https://cdn.linkfile.io/linkfile-favc.png">
  <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-slate-50 text-slate-900">
    ${opts.nonav ? "" : nav(session)}
    <main class="max-w-6xl mx-auto p-6">${body}</main>
  </body></html>`);
}
function nav(session){
  return `<header class="bg-white border-b shadow-sm">
    <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
      <div class="flex items-center gap-2">
        <img src="https://cdn.linkfile.io/linkfile-favc.png" class="w-6 h-6" alt="logo">
        <span class="font-semibold">LinkFile Admin</span>
      </div>
      <nav class="text-sm flex gap-4">
        <a class="hover:text-blue-600" href="/admin">Dashboard</a>
        <a class="hover:text-blue-600" href="/admin/reports">Reports</a>
        <a class="hover:text-blue-600" href="/admin/files">Files</a>
        <a class="hover:text-blue-600" href="/admin/users">Employees</a>
        <a class="hover:text-blue-600" href="/admin/logout">Logout</a>
      </nav>
      <div class="text-xs text-slate-600">${htmlEscape(session?.email||"")} • ${htmlEscape(session?.role||"")}</div>
    </div>
  </header>`;
}

// ----------------- PAGES -----------------
function adminLoginPage(msg=""){
  return shell("Admin Login", `
  <div class="max-w-md mx-auto bg-white border rounded-xl shadow p-6 mt-10">
    <h1 class="text-2xl font-bold mb-4">Sign in</h1>
    ${msg ? `<div class="mb-3 text-sm text-red-600">${htmlEscape(msg)}</div>` : ``}
    <form method="POST" action="/admin/login" class="space-y-4">
      <div>
        <label class="block text-sm mb-1">Email</label>
        <input name="email" type="email" required class="w-full border rounded px-3 py-2">
      </div>
      <div>
        <label class="block text-sm mb-1">Password</label>
        <input name="password" type="password" required class="w-full border rounded px-3 py-2">
      </div>
      <button class="w-full bg-blue-600 hover:bg-blue-700 text-white rounded px-4 py-2">Login</button>
    </form>
  </div>`, null, { nonav:true });
}

function adminDashPage(stats, session){
  return shell("Dashboard", `
  <h1 class="text-2xl font-bold mb-6">Overview</h1>
  <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
    <div class="bg-white border rounded-xl p-5"><div class="text-slate-500 text-sm">Total Files</div><div class="text-2xl font-semibold">${stats.files}</div></div>
    <div class="bg-white border rounded-xl p-5"><div class="text-slate-500 text-sm">Unresolved Reports</div><div class="text-2xl font-semibold">${stats.reports_open}</div></div>
    <div class="bg-white border rounded-xl p-5"><div class="text-slate-500 text-sm">Downloads (7d)</div><div class="text-2xl font-semibold">${stats.dl_7d}</div></div>
    <div class="bg-white border rounded-xl p-5"><div class="text-slate-500 text-sm">Streams (7d)</div><div class="text-2xl font-semibold">${stats.stream_7d}</div></div>
  </div>
  <div class="mt-8">
    <h2 class="font-semibold mb-3">Quick search</h2>
    <form class="flex gap-2" action="/admin/files" method="GET">
      <input name="q" placeholder="name or short id" class="border rounded px-3 py-2 flex-1">
      <button class="bg-slate-800 text-white rounded px-3 py-2">Search</button>
    </form>
  </div>`, session);
}

function adminReportsPage(rows, session){
  return shell("Reports", `
  <h1 class="text-2xl font-bold mb-4">Abuse Reports</h1>
  <div class="bg-white border rounded-xl overflow-x-auto">
    <table class="min-w-full text-sm">
      <thead><tr class="bg-slate-50 text-left">
        <th class="p-3">ID</th><th class="p-3">File</th><th class="p-3">Reason</th><th class="p-3">Status</th><th class="p-3">Created</th><th class="p-3">Action</th>
      </tr></thead>
      <tbody>
      ${rows.map(r=>`<tr class="border-t">
        <td class="p-3">${r.id}</td>
        <td class="p-3"><a class="text-blue-600" href="https://linkfile.io/f/${htmlEscape(r.file_short_id)}" target="_blank">${htmlEscape(r.file_short_id)}</a></td>
        <td class="p-3">${htmlEscape(r.reason)}${r.message?`<div class="text-slate-500 text-xs">${htmlEscape(r.message)}</div>`:''}</td>
        <td class="p-3">${htmlEscape(r.status)}</td>
        <td class="p-3">${new Date((r.created_at||0)*1000).toLocaleString()}</td>
        <td class="p-3">
          ${r.status==='open'
            ? `<form method="POST" action="/admin/reports/${r.id}/resolve"><button class="bg-green-600 hover:bg-green-700 text-white text-xs rounded px-3 py-1">Resolve</button></form>`
            : `<form method="POST" action="/admin/reports/${r.id}/reopen"><button class="bg-amber-600 hover:bg-amber-700 text-white text-xs rounded px-3 py-1">Reopen</button></form>`
          }
        </td>
      </tr>`).join('')}
      </tbody>
    </table>
  </div>`, session);
}

function adminFilesListPage(q, files, session){
  return shell("Files", `
  <h1 class="text-2xl font-bold mb-4">Files</h1>
  <form class="flex gap-2 mb-4" method="GET" action="/admin/files">
    <input name="q" value="${htmlEscape(q||'')}" placeholder="Search by name or short id" class="border rounded px-3 py-2 flex-1">
    <button class="bg-slate-800 text-white rounded px-3 py-2">Search</button>
  </form>
  <div class="bg-white border rounded-xl overflow-x-auto">
    <table class="min-w-full text-sm">
      <thead><tr class="bg-slate-50 text-left">
        <th class="p-3">Short</th><th class="p-3">Name</th><th class="p-3">Size</th><th class="p-3">MIME</th><th class="p-3">Created</th><th class="p-3">Actions</th>
      </tr></thead>
      <tbody>
      ${files.map(f=>`<tr class="border-t">
        <td class="p-3">${htmlEscape(f.short_id)}</td>
        <td class="p-3">${htmlEscape(f.name||'')}</td>
        <td class="p-3">${bytesPretty(f.size||0)}</td>
        <td class="p-3">${htmlEscape(f.mime||'')}</td>
        <td class="p-3">${(f.created_at||'').toString().replace('T',' ').replace('Z','')}</td>
        <td class="p-3">
          <a class="text-blue-600 mr-3" href="https://linkfile.io/f/${htmlEscape(f.short_id)}" target="_blank">Open</a>
          <a class="text-indigo-600 mr-3" href="https://linkfile.io/s/${htmlEscape(f.short_id)}" target="_blank">Stream</a>
        </td>
      </tr>`).join('')}
      </tbody>
    </table>
  </div>`, session);
}

function adminUsersPage(users, session){
  return shell("Employees", `
  <h1 class="text-2xl font-bold mb-4">Employees</h1>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-white border rounded-xl p-6">
      <h2 class="font-semibold mb-3">Invite / Create Employee</h2>
      <form method="POST" action="/admin/users/create" class="space-y-3">
        <div><label class="block text-sm">Name</label><input name="name" class="w-full border rounded px-3 py-2"></div>
        <div><label class="block text-sm">Email</label><input name="email" type="email" required class="w-full border rounded px-3 py-2"></div>
        <div>
          <label class="block text-sm">Role</label>
          <select name="role" class="w-full border rounded px-3 py-2">
            <option value="moderator">Moderator</option>
            <option value="analyst">Analyst</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div><label class="block text-sm">Temp Password</label><input name="password" type="text" required class="w-full border rounded px-3 py-2" placeholder="Set a temporary password"></div>
        <button class="bg-blue-600 hover:bg-blue-700 text-white rounded px-4 py-2">Create</button>
      </form>
    </div>
    <div class="bg-white border rounded-xl p-6">
      <h2 class="font-semibold mb-3">Employee List</h2>
      <div class="divide-y">
        ${users.map(u=>`<div class="py-3 flex items-center justify-between">
          <div>
            <div class="font-medium">${htmlEscape(u.name||u.email)}</div>
            <div class="text-xs text-slate-500">${htmlEscape(u.email)} • ${htmlEscape(u.role)}</div>
          </div>
          <form method="POST" action="/admin/users/${u.id}/delete" onsubmit="return confirm('Delete user?');">
            <button class="text-red-600 text-sm">Delete</button>
          </form>
        </div>`).join('')}
      </div>
    </div>
  </div>`, session);
}
