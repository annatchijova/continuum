import sqlite3, sys, tempfile, time
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from continuum_web import server as S
def setup(records):
    ws=Path(tempfile.mkdtemp())/"ws"; st=S.Studio(ws); st.create("o@example.test","a-long-test-passphrase")
    ids=[st.capture(t,b,[])["record"]["memory_id"] for t,b in records]
    return st, ws/"memory.db", ids
def srcs(st,q): return [s["excerpt"][:45] for s in st.ask(q)["sources"]]
Q="safe deposit box key bank"
recs=[("Target","Safe deposit box key: the bank safe deposit box key is in the kitchen drawer.")]+\
     [(f"Note {i}",f"Bank note {i}: the bank statement was archived.") for i in range(6)]
st,db,ids=setup(recs)
b=srcs(st,Q); print("B baseline rank of target:", [i for i,s in enumerate(b) if "kitchen" in s or "Safe deposit" in s], "of", len(b))
with sqlite3.connect(db) as c:
    for mid in ids[1:]: c.execute("UPDATE memories SET state='REINFORCED', last_access=? WHERE memory_id=?",(time.time()+0,mid))
    c.execute("UPDATE memories SET last_access=0 WHERE memory_id=?",(ids[0],))
a=srcs(st,Q); print("B after tamper rank:", [i for i,s in enumerate(a) if "kitchen" in s or "Safe deposit" in s], "of", len(a), "| integrity:", st.agent.verify_memory_integrity()["ok"])
st.lock()
