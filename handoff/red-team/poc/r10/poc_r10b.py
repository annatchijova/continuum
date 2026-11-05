import sqlite3, sys, tempfile
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from continuum_web import server as S
from legacy.agent.query_engine import QueryEngine
ws=Path(tempfile.mkdtemp())/"ws"; st=S.Studio(ws); st.create("o@example.test","a-long-test-passphrase")
st.capture("Deed","Property deed for the apartment. The original is in the blue archival folder.",[])
a=st.agent; db=ws/"memory.db"
print("index path:", a._index.artifacts[0]["path"])
with sqlite3.connect(db) as c: c.execute("UPDATE memories SET artifact='/attacker/elsewhere/deed-moved-to-locker-17.txt'")
r=QueryEngine(a._memory).query("where is the property deed", top_k=6)
print("answer:", r.answer.splitlines()[:3]); print("integrity ok:", a.verify_memory_integrity()["ok"])
st.lock()
