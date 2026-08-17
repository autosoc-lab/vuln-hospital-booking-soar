#!/usr/bin/env python3
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUTO_RESPONSE_RULE_IDS = {"100174", "100179", "100180"}
MIN_AUTO_RESPONSE_LEVEL = 15
SCRIPT = os.environ.get("SOAR_RESPONSE_SCRIPT", "/opt/soar/scripts/respond-ssh-compromise.sh")
LOCK = "/tmp/soar-ssh-compromise-response.lock"


def should_respond(alert):
    rule = alert.get("rule") or {}
    rule_id = str(rule.get("id") or "")
    level = int(rule.get("level") or 0)
    groups = set(rule.get("groups") or [])
    ssh_rule = rule_id.startswith("10017") or rule_id.startswith("10018")
    if not ssh_rule and "hospital_ssh_compromise" not in groups:
        return False
    if level < MIN_AUTO_RESPONSE_LEVEL:
        return False
    return rule_id in AUTO_RESPONSE_RULE_IDS


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        if self.path != "/respond/ssh-compromise":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("content-length", "0"))
        try:
            alert = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"invalid json")
            return

        if not should_respond(alert):
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b"ignored")
            return

        if os.path.exists(LOCK):
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b"already handled")
            return

        open(LOCK, "w").close()
        with open("/tmp/soar-last-ssh-compromise-alert.json", "w") as f:
            json.dump(alert, f, ensure_ascii=False, indent=2)

        proc = subprocess.run([SCRIPT], text=True, capture_output=True)
        with open("/tmp/soar-last-ssh-compromise-response.log", "w") as f:
            f.write(proc.stdout)
            f.write(proc.stderr)

        self.send_response(200 if proc.returncode == 0 else 500)
        self.end_headers()
        self.wfile.write((proc.stdout + proc.stderr).encode())


if __name__ == "__main__":
    port = int(os.environ.get("SOAR_RESPONSE_PORT", "8088"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
