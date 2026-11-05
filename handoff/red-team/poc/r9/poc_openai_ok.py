# Positive control: a well-behaved local Responses endpoint still narrates via the real SDK.
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
class P(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_POST(self):
        req=json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        body={"id":"resp_1","object":"response","created_at":0,"status":"completed","model":req["model"],
              "output":[{"id":"msg_1","type":"message","role":"assistant","status":"completed",
                         "content":[{"type":"output_text","text":"The deed is in the blue folder.","annotations":[]}]}],
              "parallel_tool_calls":False,"tool_choice":"auto","tools":[],"store":req.get("store")}
        b=json.dumps(body).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
        print("provider saw store=",req.get("store"))
s=ThreadingHTTPServer(("127.0.0.1",0),P); threading.Thread(target=s.serve_forever,daemon=True).start()
os.environ.update(OPENAI_API_KEY="sk-x",CONTINUUM_LLM_PROVIDER="openai",OPENAI_BASE_URL=f"http://127.0.0.1:{s.server_port}/v1",OPENAI_MAX_RETRIES="0")
from continuum_web import narrator as N
print("narration:", N.narrate("Where is the deed?","Found 1 item",["deed in the blue folder"]))
