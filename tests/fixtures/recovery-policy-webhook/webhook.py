#!/usr/bin/env python3
"""Allow requests while exposing one out-of-band effect per real AdmissionReview."""

import http.server
import json
import ssl

MAX_BODY_BYTES = 1 << 20
OPERATION_ANNOTATION = "kapsel.dev/kap0038-operation-id"


class AdmissionHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("content-length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            self.send_error(400)
            return
        review = json.loads(self.rfile.read(length))
        request = review["request"]
        if not request.get("dryRun", False):
            annotations = request.get("object", {}).get("metadata", {}).get("annotations", {})
            operation_id = annotations.get(OPERATION_ANNOTATION, "missing")
            print(
                f"KAPSEL_ADMISSION_EFFECT uid={request['uid']} operation_id={operation_id}",
                flush=True,
            )
        response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {"uid": request["uid"], "allowed": True},
        }
        encoded = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), AdmissionHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
