import sys, tempfile, threading, subprocess
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from continuum_web import server as S
studio=S.Studio(Path(tempfile.mkdtemp())/"ws"); studio.create("owner@example.test","a-long-test-passphrase")
H=type("H",(S.Handler,),{"studio":studio}); srv=ThreadingHTTPServer(("127.0.0.1",0),H)
threading.Thread(target=srv.serve_forever,daemon=True).start()
d=Path(tempfile.mkdtemp()); (d/"index.html").write_text("<p>evil</p>")
class E(SimpleHTTPRequestHandler):
    def __init__(s,*a,**k): super().__init__(*a,directory=str(d),**k)
    def log_message(s,*a): pass
evil=ThreadingHTTPServer(("127.0.0.1",0),E); threading.Thread(target=evil.serve_forever,daemon=True).start()
subprocess.run(["node",str(__import__("pathlib").Path(__file__).with_name("browser.js")),str(srv.server_port),str(evil.server_port)],check=True)
print("artifacts:",studio.snapshot()["total_artifacts"],"| still open:",studio.agent is not None)
studio.lock()
