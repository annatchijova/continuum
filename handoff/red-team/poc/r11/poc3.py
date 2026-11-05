import sqlite3, sys, tempfile, time
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from continuum_web import server as S
ws=Path(tempfile.mkdtemp())/"ws"; st=S.Studio(ws); st.create("o@example.test","a-long-test-passphrase")
tid=st.capture("Target","Safe deposit box key: the bank safe deposit box key is in the kitchen drawer.",[])["record"]["memory_id"]
ids=[st.capture(f"Note {i}",f"Bank note {i}: the bank statement was archived.",[])["record"]["memory_id"] for i in range(6)]
Q="safe deposit box key bank"; mem=st.agent._memory
def rank(): r=mem.recall(Q, top_k=6); return [x.memory_id for x in r].index(tid) if tid in [x.memory_id for x in r] else None, [round(x.final_score,3) for x in r]
print("baseline (unfiltered top6):", rank())
with sqlite3.connect(ws/"memory.db") as c:
    for m in ids: c.execute("UPDATE memories SET state='REINFORCED', last_access=? WHERE memory_id=?",(time.time(),m))
    c.execute("UPDATE memories SET last_access=0 WHERE memory_id=?",(tid,))
print("after promoting 6 decoys:", rank(), "| integrity:", st.agent.verify_memory_integrity()["ok"])
st.lock()
