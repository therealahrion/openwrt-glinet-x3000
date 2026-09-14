#!/usr/bin/env python3
"""Saturate the Wi-Fi downlink from a wired host, without writing anything to
the client's storage.

The A/B in wifiab.sh needs LAN-side traffic that keeps the radio busy for about
three minutes. Fetching a file in a loop is a poor fit: a sysupgrade image is
roughly a second of transfer at Wi-Fi rates, so most of the run would be
connection setup, and the phone would save hundreds of copies.

This serves two things instead:

    /          a page that fetches /stream and throws the bytes away as they
               arrive, so the client holds nothing on disk and the transfer can
               run indefinitely
    /stream    an endless octet-stream

Run it on the WIRED machine:

    python wifiload.py                     random bytes, unlimited
    python wifiload.py C:\path\to\Test.7z   that file, on repeat

Either source works. What matters is that the bytes are incompressible, so
nothing along the path can inflate the result: os.urandom and an already
compressed archive are equivalent on that point. Looping a real file is there
so a file already on disk can drive the test without its size limiting the run
and without writing a byte to the client.

Then open http://<this-machine's LAN IP>:8000/ on the Wi-Fi client and leave
the screen on - a sleeping phone screen throttles Wi-Fi and would show up as a
fake drop mid-test.
"""

import http.server
import os
import socket
import socketserver
import sys

PORT = 8000
CHUNK = os.urandom(1 << 20)  # 1 MiB, generated once and resent

# An optional real file to send on repeat instead of random bytes. Passing one
# changes nothing about the measurement - an already-compressed file and
# os.urandom are equally incompressible, which is the only property that
# matters here - but it lets a file already on disk drive the test without
# writing a byte to the client, because the page discards what it reads.
SOURCE = sys.argv[1] if len(sys.argv) > 1 else None

PAGE = b"""<!doctype html>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wi-Fi load</title>
<body style="font:16px system-ui,sans-serif;margin:0;padding:24px;background:#111;color:#eee">
<h2 style="margin:0 0 16px">Wi-Fi load generator</h2>
<div id="rate" style="font:600 40px ui-monospace,monospace;margin-bottom:8px">--</div>
<div id="tot" style="color:#888"></div>
<p style="color:#888;margin-top:24px">Keep this screen on and the tab in the
foreground. Close the tab to stop.</p>
<script>
let total = 0, last = 0, lastT = Date.now();
const rate = document.getElementById('rate'), tot = document.getElementById('tot');

// The DOM is updated on a timer rather than per chunk: at these rates a write
// per chunk costs more than the download does.
setInterval(() => {
  const now = Date.now(), dt = (now - lastT) / 1000;
  if (dt > 0) {
    rate.textContent = ((total - last) * 8 / 1e6 / dt).toFixed(0) + ' Mbit/s';
    tot.textContent = (total / 1048576).toFixed(0) + ' MiB received and discarded';
  }
  last = total; lastT = now;
}, 1000);

async function run() {
  while (true) {
    try {
      // Cache-buster so no layer short-circuits the request.
      const res = await fetch('/stream?x=' + Math.random());
      const reader = res.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;   // value goes out of scope here - nothing is kept
      }
    } catch (e) {
      rate.textContent = 'reconnecting';
    }
    await new Promise(r => setTimeout(r, 200));
  }
}
run();
</script>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/stream"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "no-store")
            # No Content-Length: this is a connection-close stream of unknown
            # length, which is what lets it run until the client goes away.
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                if SOURCE:
                    # Loop the file rather than sending it once, so the stream
                    # never ends and no restart lands inside a measurement
                    # interval - a gap there reads as a throughput drop, which
                    # is the signal the A/B is trying to measure.
                    while True:
                        with open(SOURCE, "rb") as fh:
                            while True:
                                buf = fh.read(1 << 20)
                                if not buf:
                                    break
                                self.wfile.write(buf)
                else:
                    while True:
                        self.wfile.write(CHUNK)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass  # the client closed the tab or moved on; expected
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *args):
        pass  # one line per chunk would itself become the bottleneck


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def lan_ips():
    out = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in out:
                out.append(ip)
    except OSError:
        pass
    return out


if __name__ == "__main__":
    if SOURCE and not os.path.isfile(SOURCE):
        print("no such file: %s" % SOURCE)
        raise SystemExit(1)
    ips = lan_ips()
    if SOURCE:
        print("streaming %s (%.1f GB) on repeat" % (SOURCE, os.path.getsize(SOURCE) / 1e9))
    else:
        print("streaming random bytes")
    print("serving on port %d" % PORT)
    for ip in ips:
        print("  open on the Wi-Fi client:  http://%s:%d/" % (ip, PORT))
    if not ips:
        print("  (could not determine this machine's LAN IP - use ipconfig)")
    print("Ctrl-C to stop.")
    with Server(("", PORT), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
