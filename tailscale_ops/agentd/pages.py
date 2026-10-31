"""The pages the owner opens: approve or deny one request, and enrol a passkey. Plain HTML from the
service itself; the script is one static file, so the pages run under a strict CSP."""

import html
import json

CSP = ("default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

STYLE = """
:root { color-scheme: light dark; --fg: #1d1d1f; --muted: #6e6e73; --bg: #f5f5f7; --card: #fff; --line: #d2d2d7;
        --ok: #1a7f37; --bad: #c62828; --accent: #0a66d8; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #f5f5f7; --muted: #a1a1a6; --bg: #000; --card: #1c1c1e; --line: #38383a;
          --ok: #4ac26b; --bad: #ff6b6b; --accent: #4c9bff; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
       font: 16px/1.5 -apple-system, BlinkMacSystemFont, "PingFang SC", "Helvetica Neue", sans-serif; }
main { max-width: 560px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color: var(--muted); margin: 0 0 20px; font-size: 14px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 4px 16px; }
.row { display: flex; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--line); }
.row:last-child { border-bottom: 0; }
.row b { flex: 0 0 96px; color: var(--muted); font-weight: 500; }
.row span { flex: 1; overflow-wrap: anywhere; }
.note { color: var(--muted); font-size: 14px; margin: 16px 0; }
.actions { display: flex; gap: 12px; margin-top: 20px; }
button { flex: 1; font: inherit; font-weight: 600; padding: 14px; border-radius: 12px; border: 0; cursor: pointer; }
#approve, #enroll, #create { background: var(--accent); color: #fff; }
#list, .small { background: transparent; color: var(--accent); border: 1px solid var(--line); }
.small { flex: 0 0 auto; padding: 6px 12px; font-size: 14px; }
input { font: inherit; width: 100%; padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px;
        background: var(--bg); color: var(--fg); }
code.secret { display: block; padding: 10px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg);
              overflow-wrap: anywhere; font-size: 14px; }
.copy { display: flex; gap: 8px; align-items: center; margin: 8px 0 14px; }
.copy code { flex: 1; }
#deny { background: transparent; color: var(--bad); border: 1px solid var(--line); }
button:disabled { opacity: .5; }
.status { font-size: 18px; font-weight: 600; margin: 20px 0 8px; }
.ok { color: var(--ok); } .bad { color: var(--bad); }
#msg { min-height: 1.5em; margin-top: 16px; }
"""

STATUS = {
    "pending": ("", "等待你的决定"),
    "approved": ("ok", "已批准，正在加入"),
    "done": ("ok", "已加入"),
    "denied": ("bad", "已拒绝"),
    "expired": ("bad", "已过期，没有人批准"),
    "failed": ("bad", "批准了，但 Headscale 没有接受"),
}


LEAVE_STATUS = dict(STATUS, approved=("ok", "已批准，正在移除"), done=("ok", "已退出"),
                    expired=("bad", "已过期，没有人批准"), failed=("bad", "批准了，但没有移除（见下）"))


def _page(title, body, data=None):
    attrs = "".join(f' data-{k}="{html.escape(str(v))}"' for k, v in (data or {}).items())
    return (f'<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
            f"<body><main{attrs}>{body}</main><script src=\"/static/app.js\"></script></body></html>")


def _rows(pairs):
    return '<div class="card">' + "".join(
        f'<div class="row"><b>{html.escape(k)}</b><span>{v}</span></div>' for k, v in pairs) + "</div>"


def _when(seconds):
    return f'<time data-ts="{int(seconds)}">{int(seconds)}</time>'


def leave_approval(req, config):
    e = html.escape
    n = req.get("node") or {}
    rows = [
        ("机器名", f"<strong>{e(req['name'])}</strong>"),
        ("内网地址", e(n.get("ipv4") or "—")),
        ("状态", ("在线" if n.get("online") else "离线") + (f" · 最近在线 {e(n['last_seen'])}" if n.get("last_seen") else "")),
        ("tag", e(", ".join(req["tags"])) + ' <small class="note">（通过 tn-agent 入网的机器）</small>'),
        ("网络", f"{e(req['region'])} · {e(config['login_server'])}"),
        ("说明", e(req["reason"]) + ' <small class="note">（Agent 写的）</small>' if req["reason"] else "—"),
        ("发起", f"{e(req['who'])} · {_when(req['created'])}"),
        ("有效到", _when(req["expires"])),
        ("请求", f"<code>{e(req['id'])}</code> · 节点 {e(str(n.get('id')))}"),
    ]
    cls, label = LEAVE_STATUS[req["status"]]
    body = [f"<h1>让 {e(req['name'])} 退出 {e(req['region'])}？</h1>",
            '<p class="sub">tailscale-ops · 这一页由控制机自己提供，内容以这里为准</p>', _rows(rows)]
    if req["status"] == "pending":
        body += ['<p class="note">批准后，tn-agent 从 Headscale 删掉这个节点，它马上断开、再也连不上；要回来得重新入网。'
                 "机器上的 Tailscale 由 Agent 之后清理。批准和拒绝都要 passkey。</p>",
                 '<div class="actions"><button id="approve">批准</button><button id="deny">拒绝</button></div>']
    else:
        body.append(f'<p class="status {cls}">{e(label)}</p>')
        if req.get("error"):
            body.append(f'<p class="bad">{e(req["error"])}</p>')
    body.append('<p id="msg"></p>')
    return _page(f"{req['name']} · 退出审批", "".join(body), {"page": "approve", "request": req["id"]})


def approval(req, config):
    if req.get("kind") == "leave":
        return leave_approval(req, config)
    e = html.escape
    m = req.get("machine") or {}
    rows = [
        ("机器名", f"<strong>{e(req['name'])}</strong>"),
        ("公网 IP", f"<strong>{e(m.get('ip') or '?')}</strong>"),
        ("它报告", e(" · ".join(x for x in (m.get("hostname"), m.get("os"), m.get("arch")) if x) or "—")),
        ("tag", e(", ".join(req["tags"])) + ' <small class="note">（不能主动连别的机器）</small>'),
        ("网络", f"{e(req['region'])} · {e(config['login_server'])}"),
        ("说明", e(req["reason"]) + ' <small class="note">（Agent 写的）</small>' if req["reason"] else "—"),
        ("发起", f"{e(req['who'])} · {_when(req['created'])}"),
        ("有效到", _when(req["expires"])),
        ("请求", f"<code>{e(req['id'])}</code> · auth-id …{e(req['auth_id'][-6:])}"),
    ]
    cls, label = STATUS[req["status"]]
    body = [f"<h1>让 {e(req['name'])} 加入 {e(req['region'])}？</h1>",
            '<p class="sub">tailscale-ops · 这一页由控制机自己提供，内容以这里为准</p>', _rows(rows)]
    if req["status"] == "pending":
        body += ['<p class="note">公网 IP 是 tn-agent 收到这台机器登录时看到的来源地址，主机名和系统由机器自己报告。'
                 "先核对 IP 是不是你要加的那台机器，再批准。批准和拒绝都要 passkey（面容 ID、触控 ID 或设备密码）。</p>",
                 '<div class="actions"><button id="approve">批准</button><button id="deny">拒绝</button></div>']
    else:
        body.append(f'<p class="status {cls}">{e(label)}</p>')
        result = req.get("result")
        if result:
            body.append(_rows([("名字", e(result.get("name") or "")), ("地址", e(result.get("ipv4") or "")),
                               ("tag", e(", ".join(result.get("tags") or []))),
                               ("自报主机名", e(result.get("hostname") or ""))]))
        if req.get("error"):
            body.append(f'<p class="bad">{e(req["error"])}</p>')
    body.append('<p id="msg"></p>')
    return _page(f"{req['name']} · 入网审批", "".join(body), {"page": "approve", "request": req["id"]})


def enrolment(config):
    e = html.escape
    body = (f"<h1>登记 passkey</h1><p class=\"sub\">tailscale-ops · 网络 {e(config['region'])}</p>"
            '<p class="note">登记以后，Agent 发来的每个改动都要用这把 passkey 批准。用 Safari 登记的 passkey 存在 '
            "iCloud 钥匙串里，会同步到你的 iPhone 和 Mac。这个链接只能用一次，几分钟后失效。</p>"
            '<div class="actions"><button id="enroll">登记</button></div><p id="msg"></p>')
    return _page("登记 passkey · tailscale-ops", body, {"page": "enroll"})


def tokens(config):
    e = html.escape
    body = (f"<h1>MCP 令牌</h1><p class=\"sub\">tailscale-ops · 网络 {e(config['region'])}</p>"
            '<p class="note">Agent 平台用令牌连上这里的 MCP。有了令牌，Agent 只能查看网络、申请让机器入网；每次入网'
            "仍然要你在审批页上用 passkey 批准。生成、查看、撤销令牌都要 passkey。</p>"
            '<div class="card"><div class="row"><b>名字</b><span><input id="label" value="agent" maxlength="40" '
            'autocomplete="off"></span></div></div>'
            '<div class="actions"><button id="create">生成令牌</button><button id="list">查看已有令牌</button></div>'
            '<div id="made" hidden><p class="status ok">令牌只显示这一次，请现在复制。</p>'
            '<b>令牌</b><div class="copy"><code class="secret" id="token"></code>'
            '<button class="small" data-copy="token">复制</button></div>'
            '<b>MCP 地址</b><div class="copy"><code class="secret" id="mcp"></code>'
            '<button class="small" data-copy="mcp">复制</button></div>'
            '<b>请求头</b><div class="copy"><code class="secret" id="header"></code>'
            '<button class="small" data-copy="header">复制</button></div>'
            '<p class="note">在 Agent 平台加一个自定义 MCP 服务器，填上地址，认证方式选请求头：名字 Authorization，'
            "值 Bearer 加令牌（上面一行就是）。</p></div>"
            '<div id="tokens"></div><p id="msg"></p>')
    return _page("MCP 令牌 · tailscale-ops", body, {"page": "tokens"})


def message(title, text):
    return _page(title, f"<h1>{html.escape(title)}</h1><p class=\"note\">{html.escape(text)}</p>")


SCRIPT = r"""
"use strict";
const main = document.querySelector("main");
const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const say = (text, bad) => { const m = document.getElementById("msg"); m.textContent = text; m.className = bad ? "bad" : ""; };
const buttons = (on) => document.querySelectorAll("button").forEach((b) => { b.disabled = !on; });

async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({ error: r.statusText }));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

async function decide(decision) {
  const id = main.dataset.request;
  buttons(false);
  say(decision === "approve" ? "等待 passkey…" : "用 passkey 确认拒绝…");
  try {
    const o = await post(`/a/${id}/begin`, { decision });
    const c = await navigator.credentials.get({ publicKey: {
      challenge: dec(o.challenge), rpId: o.rpId, userVerification: "required", timeout: o.timeout,
      allowCredentials: o.allowCredentials.map((x) => ({ type: "public-key", id: dec(x) })) } });
    say("正在执行…");
    await post(`/a/${id}/finish`, { decision, id: c.id, clientDataJSON: enc(c.response.clientDataJSON),
      authenticatorData: enc(c.response.authenticatorData), signature: enc(c.response.signature) });
    location.reload();
  } catch (e) {
    say(e.name === "NotAllowedError" ? "已取消，或者这台设备上没有登记过的 passkey。" : e.message, true);
    buttons(true);
  }
}

async function enroll() {
  const code = location.hash.slice(1);
  buttons(false);
  try {
    const o = await post("/enroll/begin", { code });
    const c = await navigator.credentials.create({ publicKey: {
      challenge: dec(o.challenge), rp: o.rp, timeout: o.timeout, attestation: "none",
      user: { id: dec(o.user.id), name: o.user.name, displayName: o.user.displayName },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      excludeCredentials: o.excludeCredentials.map((x) => ({ type: "public-key", id: dec(x) })) } });
    const r = await post("/enroll/finish", { code, label: navigator.userAgent.slice(0, 60),
      clientDataJSON: enc(c.response.clientDataJSON), attestationObject: enc(c.response.attestationObject) });
    history.replaceState(null, "", location.pathname);
    say(`已登记。这里现在有 ${r.passkeys} 把 passkey。`);
  } catch (e) {
    say(e.name === "NotAllowedError" ? "已取消。" : e.message, true);
    buttons(true);
  }
}

async function withPasskey(base, body) {
  const o = await post(`${base}/begin`, body);
  const c = await navigator.credentials.get({ publicKey: {
    challenge: dec(o.challenge), rpId: o.rpId, userVerification: "required", timeout: o.timeout,
    allowCredentials: o.allowCredentials.map((x) => ({ type: "public-key", id: dec(x) })) } });
  return post(`${base}/finish`, { ...body, id: c.id, clientDataJSON: enc(c.response.clientDataJSON),
    authenticatorData: enc(c.response.authenticatorData), signature: enc(c.response.signature) });
}

const when = (s) => (s ? new Date(s * 1000).toLocaleString() : "—");

function showTokens(list) {
  const box = document.getElementById("tokens");
  box.replaceChildren();
  if (!list.length) { box.textContent = "还没有在这里生成的令牌。"; return; }
  const card = document.createElement("div");
  card.className = "card";
  for (const t of list) {
    const row = document.createElement("div");
    row.className = "row";
    const name = document.createElement("b");
    name.textContent = t.label;
    const info = document.createElement("span");
    info.textContent = `生成于 ${when(t.created)} · 最近使用 ${when(t.last_used)}`;
    const revoke = document.createElement("button");
    revoke.className = "small";
    revoke.textContent = "撤销";
    revoke.onclick = () => tokens("revoke", t.id);
    row.append(name, info, revoke);
    card.append(row);
  }
  box.append(card);
}

async function tokens(action, subject) {
  buttons(false);
  say("等待 passkey…");
  try {
    const r = await withPasskey("/tokens", { action, subject });
    if (r.token) {
      document.getElementById("token").textContent = r.token;
      document.getElementById("mcp").textContent = r.mcp_url;
      document.getElementById("header").textContent = `Bearer ${r.token}`;
      document.getElementById("made").hidden = false;
    }
    showTokens(r.tokens);
    say(action === "create" ? "已生成。" : action === "revoke" ? "已撤销；用它的 Agent 连不上了。" : "");
  } catch (e) {
    say(e.name === "NotAllowedError" ? "已取消，或者这台设备上没有登记过的 passkey。" : e.message, true);
  }
  buttons(true);
}

document.querySelectorAll("time[data-ts]").forEach((t) => { t.textContent = new Date(t.dataset.ts * 1000).toLocaleString(); });
document.querySelectorAll("button[data-copy]").forEach((b) => {
  b.onclick = async () => {
    await navigator.clipboard.writeText(document.getElementById(b.dataset.copy).textContent);
    say("已复制。");
  };
});
if (main.dataset.page === "approve") {
  const a = document.getElementById("approve"), d = document.getElementById("deny");
  if (a) a.onclick = () => decide("approve");
  if (d) d.onclick = () => decide("deny");
} else if (main.dataset.page === "enroll") {
  document.getElementById("enroll").onclick = enroll;
} else if (main.dataset.page === "tokens") {
  document.getElementById("create").onclick = () => tokens("create", document.getElementById("label").value);
  document.getElementById("list").onclick = () => tokens("list", "");
}
"""


def json_body(value):
    return json.dumps(value, ensure_ascii=False).encode()
