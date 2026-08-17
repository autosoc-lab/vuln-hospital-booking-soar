#!/usr/bin/env python3
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROUTES = {
    "/respond/ssh-compromise": {
        "script": os.environ.get(
            "SOAR_RESPONSE_SCRIPT", "/opt/soar/scripts/respond-ssh-compromise.sh"
        ),
        "rule_ids": {"100174", "100179", "100180"},
        "min_level": 15,
        "require_group": "hospital_ssh_compromise",
        "lock": "/tmp/soar-ssh-compromise-response.lock",
    },
    # SSE-C 랜섬웨어 체인 - lifecycle 원복. 되돌리기 쉽고 부작용이 거의 없는 조치라
    # 레벨과 무관하게(100031은 level 10) 승인 없이 자동 실행한다.
    "/respond/lifecycle-revert": {
        "script": "/opt/soar/scripts/respond-lifecycle-revert.sh",
        "rule_ids": {"100031", "100032"},
        "min_level": 0,
        "require_group": None,
        "lock": None,
    },
    # SSRF->IMDS 탈취 / SSE-C 반출 - STS 세션 revoke. 앱 EC2가 완전히 막히는
    # 부작용이 있는 조치라 100014/100034(확증, 승인 불필요)만 실제로 연결돼있다.
    # 100013/100033(미확증, 승인 필요)은 허용 목록엔 있지만 아직 그쪽을 호출하는
    # Shuffle 브랜치가 없다 - 승인 노드를 나중에 붙이면 API 재배포 없이 바로 연결된다.
    "/respond/session-revoke": {
        "script": "/opt/soar/scripts/respond-session-revoke.sh",
        "rule_ids": {"100013", "100014", "100033", "100034"},
        "min_level": 0,
        "require_group": None,
        "lock": None,
    },
}


def should_respond(route, alert):
    rule = alert.get("rule") or {}
    rule_id = str(rule.get("id") or "")
    level = int(rule.get("level") or 0)
    groups = set(rule.get("groups") or [])

    if route["require_group"] and route["require_group"] not in groups:
        return False
    if level < route["min_level"]:
        return False
    return rule_id in route["rule_ids"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        route = ROUTES.get(self.path)
        if route is None:
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

        if not should_respond(route, alert):
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b"ignored")
            return

        lock = route["lock"]
        if lock and os.path.exists(lock):
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b"already handled")
            return

        if lock:
            open(lock, "w").close()

        tag = self.path.strip("/").replace("/", "-")
        proc = None
        try:
            with open(f"/tmp/soar-last-{tag}-alert.json", "w") as f:
                json.dump(alert, f, ensure_ascii=False, indent=2)

            proc = subprocess.run([route["script"]], text=True, capture_output=True)
            with open(f"/tmp/soar-last-{tag}-response.log", "w") as f:
                f.write(proc.stdout)
                f.write(proc.stderr)
        finally:
            if lock and (proc is None or proc.returncode != 0):
                try:
                    os.remove(lock)
                except FileNotFoundError:
                    pass

        self.send_response(200 if proc.returncode == 0 else 500)
        self.end_headers()
        self.wfile.write((proc.stdout + proc.stderr).encode())


if __name__ == "__main__":
    port = int(os.environ.get("SOAR_RESPONSE_PORT", "8088"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
