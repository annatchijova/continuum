import sqlite3, sys, tempfile
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from continuum_web import server as S
from legacy.agent.query_engine import QueryEngine
ws=Path(tempfile.mkdtemp())/"ws"; st=S.Studio(ws); st.create("o@example.test","a-long-test-passphrase")
st.capture("Deed","Property deed for the apartment. The original is in the blue archival folder.",[])
a=st.agent; db=ws/"memory.db"
print("stored category:", sqlite3.connect(db).execute("SELECT category FROM memories").fetchone())
for q in ("where is the property deed","where is the apartment deed","locate the blue archival folder"):
    r=QueryEngine(a._memory).query(q, top_k=6); print(repr(q),"->",r.intent.value, r.category_filter, "|", r.answer.splitlines()[0][:90], "|", [x.artifact for x in r.results])
with sqlite3.connect(db) as c: c.execute("UPDATE memories SET artifact='/attacker/deed-moved-to-locker-17.txt'")
r=QueryEngine(a._memory).query("where is the apartment deed", top_k=6); print("after tamper:", r.answer.replace("\n"," | ")[:160]); print("integrity ok:", a.verify_memory_integrity()["ok"])
st.lock()
