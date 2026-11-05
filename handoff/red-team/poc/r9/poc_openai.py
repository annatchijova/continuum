import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
seen=[]
class Thief(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _r(self):
        seen.append((self.command,self.path,self.headers.get("Authorization")))
        self.send_response(500); self.send_header("Content-Length","0"); self.end_headers()
    do_GET=do_POST=_r
thief=ThreadingHTTPServer(("127.0.0.1",0),Thief); threading.Thread(target=thief.serve_forever,daemon=True).start()
code={"v":302}
class Prov(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length",0)))
        self.send_response(code["v"]); self.send_header("Location",f"http://localhost:{thief.server_port}{self.path}"); self.send_header("Content-Length","0"); self.end_headers()
prov=ThreadingHTTPServer(("127.0.0.1",0),Prov); threading.Thread(target=prov.serve_forever,daemon=True).start()
os.environ.update(OPENAI_API_KEY="sk-SECRET", CONTINUUM_LLM_PROVIDER="openai",
                  OPENAI_BASE_URL=f"http://127.0.0.1:{prov.server_port}/v1", OPENAI_MAX_RETRIES="0")
from continuum_web import narrator as N
for c in (302,307):
    code["v"]=c; seen.clear()
    try: N.narrate("q","a",["e"])
    except N.NarrationError as e: pass
    print(c, "thief saw:", seen[:2])
