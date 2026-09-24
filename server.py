#!/usr/bin/env python3
# slopkit modification -- LAN server
#

import os
import re
import sys
import json
import time
import hashlib
import socket
import threading
import http.server
import urllib.parse

ROOT = os.path.dirname(os.path.abspath(__file__))
MANIFEST_NAME = "slopkit.appcache"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
JAIL_PORT = 9021
PAYLOAD_DIR = os.path.join(ROOT, "payloads")


def probe_tcp(ip, port, timeout=1.5):

    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def send_payload_to(ip, name):

    if not re.match(r"^[A-Za-z0-9._-]+\.(elf|bin)$", name):
        return {"ok": False, "why": "bad payload name"}
    path = os.path.join(PAYLOAD_DIR, name)
    if not os.path.isfile(path):
        return {"ok": False, "why": "no such payload"}
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"ok": False, "why": "read failed: %s" % e}
    try:
        s = socket.create_connection((ip, JAIL_PORT), timeout=5)
        s.settimeout(20)
        s.sendall(data)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        s.close()
        return {"ok": True, "bytes": len(data), "ip": ip}
    except OSError as e:
        return {"ok": False, "why": "connect/send failed: %s" % e}


def build_manifest():

    with open(os.path.join(ROOT, MANIFEST_NAME), "r",
              encoding="utf-8", errors="replace") as f:
        text = f.read()
    paths = set(["index.html"])
    for line in text.splitlines():
        l = line.strip()
        if (not l or l.startswith("#") or l in
                ("CACHE MANIFEST", "CACHE:", "NETWORK:", "FALLBACK:", "*")):
            continue
        paths.add(l.split("?")[0])

    h = hashlib.sha1()
    for rel in sorted(paths):
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        try:
            st = os.stat(p)
            h.update(("%s:%d:%d\n" % (rel, st.st_size, int(st.st_mtime)))
                     .encode("utf-8"))
        except OSError:
            h.update((rel + ":MISSING\n").encode("utf-8"))
    fp = h.hexdigest()[:10]

    out = []
    for line in text.splitlines():
        if line.startswith("# auto-fingerprint:"):
            out.append("# auto-fingerprint: " + fp)
        else:
            out.append(line)
    return ("\n".join(out) + "\n").encode("utf-8")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def guess_type(self, path):
        p = path.split("?")[0]
        if p.endswith(".appcache"):
            return "text/cache-manifest; charset=utf-8"
        if p.endswith(".js"):
            return "text/javascript; charset=utf-8"
        if p.endswith(".elf") or p.endswith(".bin"):
            return "application/octet-stream"
        return super().guess_type(path)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/__jailcheck":
            ip = self.client_address[0]
            open_ = probe_tcp(ip, JAIL_PORT)
            self._json({"open": open_, "ip": ip})
            return
        if path.endswith(".appcache"):
            self._serve_manifest(head=False)
        else:
            super().do_GET()

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        if self.path.split("?")[0].endswith(".appcache"):
            self._serve_manifest(head=True)
        else:
            super().do_HEAD()

    def _serve_manifest(self, head):
        try:
            body = build_manifest()
        except OSError:
            self.send_error(404, "manifest not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/cache-manifest; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/__sendpayload":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = (q.get("name") or [""])[0]
            try:
                delay_ms = int((q.get("delay") or ["0"])[0])
            except ValueError:
                delay_ms = 0
            delay_ms = max(0, min(30000, delay_ms))
            ip = self.client_address[0]
            if delay_ms:
                # mod: scheduled send -- the browser page closes right after
                # the PS notification; this timer lives on the PC and delivers
                # the payload to elfldr on time regardless.
                def _later(ip=ip, name=name, delay_ms=delay_ms):
                    time.sleep(delay_ms / 1000.0)
                    send_payload_to(ip, name)
                threading.Thread(target=_later, daemon=True).start()
                self._json({"ok": True, "queued": True,
                            "delay": delay_ms, "name": name})
                return
            res = send_payload_to(ip, name)
            self._json(res, 200 if res.get("ok") else 502)
            return
        if path != "/__poops_log":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        text = body.decode("utf-8", "replace").replace("\r", " ").replace("\n", " ")
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(os.path.join(ROOT, "poops_log.txt"), "a",
                      encoding="utf-8") as f:
                f.write("[%s] %s\n" % (stamp, text[:4000]))
        except OSError:
            pass
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt, *args):
        sys.stdout.write("%s - %s\n" % (self.address_string(), fmt % args))


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def lan_addresses():
    out = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        for info in infos:
            ip = info[4][0]
            if ip not in out and not ip.startswith("127."):
                out.append(ip)
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 1))
        ip = s.getsockname()[0]
        s.close()
        if ip not in out:
            out.insert(0, ip)
    except OSError:
        pass
    return out or ["<your-PC-ip>"]


if __name__ == "__main__":
    print("slopkit server")
    print("serving: %s" % ROOT)
    for ip in lan_addresses():
        print("open on PS5:  http://%s:%d/" % (ip, PORT))
    print("press Ctrl+C to stop")
    Server(("", PORT), Handler).serve_forever()
