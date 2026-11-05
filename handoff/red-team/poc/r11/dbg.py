import sys, tempfile
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from continuum_web import server as S
from legacy.agent.query_engine import QueryEngine
ws=Path(tempfile.mkdtemp())/"ws"; st=S.Studio(ws); st.create("o@example.test","a-long-test-passphrase")
st.capture("Target","Safe deposit box key: the bank safe deposit box key is in the kitchen drawer.",[])
for i in range(6): st.capture(f"Note {i}",f"Bank note {i}: the bank statement was archived.",[])
Q="safe deposit box key bank"
an=QueryEngine(st.agent._memory).analyze(Q); print("intent:",an.intent, "cat:",an.detected_category)
import sqlite3; print(sqlite3.connect(ws/"memory.db").execute("SELECT category, count(*) FROM memories GROUP BY category").fetchall())
for r in st.agent._memory.recall(Q, top_k=10): print(round(r.relevance if hasattr(r,'relevance') else 0,3), r.category.value, r.content[:50])
print([ (k,getattr(r,k)) for k in ('score',) ] if False else "")
st.lock()
