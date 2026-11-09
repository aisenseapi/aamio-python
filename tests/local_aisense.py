"""aisenseapi.com on this machine, for the add-ons' tests: a receiver that reads every request to the end and answers as it is told.

It stands in for the cases a fake encode or decode cannot show: the request,
card, picture or recording and all, had reached the service before it
answered 503, or the answer broke off after its head.
"""

import http.server
import threading
import time
import urllib.request


class Receiver:
    """Keeps every request body, and answers each with answer(handler)."""

    def __init__(self, answer):
        outer = self
        self.bodies = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                outer.bodies.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                answer(self)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    @property
    def base(self):
        return "http://127.0.0.1:%d/services/v1" % self.server.server_address[1]


def busy(handler):
    """503 with Retry-After, after the whole request was read."""
    body = b'{"error": "Busy."}'
    handler.send_response(503)
    handler.send_header("Retry-After", "5")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def cut(handler):
    """A 200 that promises a thousand bytes and closes after one."""
    handler.send_response(200)
    handler.send_header("Content-Length", "1000")
    handler.end_headers()
    handler.wfile.write(b"{")
    handler.close_connection = True


def stall(handler):
    """A 200 that promises a thousand bytes and goes quiet for longer than a test's timeout."""
    handler.send_response(200)
    handler.send_header("Content-Length", "1000")
    handler.end_headers()
    handler.wfile.write(b"{")
    handler.wfile.flush()
    time.sleep(2)


def direct(request, timeout=None):
    """urlopen without proxies, so the receiver on this machine is reached whatever the environment says."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout)
