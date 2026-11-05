import json, sqlite3, sys, tempfile, time
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from continuum_web import server as S, narrator as N
from legacy.agent.query_engine import QueryEngine
from legacy.ingestion.doc_types import DocCategory

# C3: egress scope
ws=Path(tempfile.mkdtemp())/"ws"; st=S.Studio(ws); st.create("o@example.test","a-long-test-passphrase")
long = "Last will and testament. " + " ".join(f"clause{i} secret{i}" for i in range(80))
st.capture("Will", long, [])
sent={}
N.enabled=lambda *, opted_in: opted_in
N.narrate=lambda q,a,ex: sent.update(answer=a, ex=list(ex)) or "ok"
st.ask("will testament", allow_narration=True)
print("C3 excerpt chars:", [len(e) for e in sent["ex"]], "| answer chars:", len(sent["answer"]),
      "| answer leaks beyond excerpt:", any(t in sent["answer"] for t in long[180:300].split()))

# C7: category flip
db=ws/"memory.db"; agent=st.agent
with sqlite3.connect(db) as c:
    rows=c.execute("SELECT memory_id, category FROM memories").fetchall()
print("C7 categories:", rows)
mid,cat=rows[0]
before=[r.memory_id for r in agent._memory.recall("will testament", category=DocCategory(cat))]
with sqlite3.connect(db) as c: c.execute("UPDATE memories SET category='personal' WHERE memory_id=?", (mid,))
after=[r.memory_id for r in agent._memory.recall("will testament", category=DocCategory(cat))]
print(f"C7 filtered recall in '{cat}': before={len(before)} after={len(after)} | integrity:", agent.verify_memory_integrity()["ok"])
st.lock()

# C5/C6: heir view
ws2=Path(tempfile.mkdtemp())/"ws"; st2=S.Studio(ws2)
st2.create("owner@example.test","a-long-test-passphrase", inactivity_days=1,
           inactivity_last_activity=__import__("datetime").datetime(2020,1,1,tzinfo=__import__("datetime").timezone.utc))
st2.lock()
snap=st2.unlock_heir("  Heir-One ", "a-long-test-passphrase")
print("C5 heir sees owner_email:", snap["owner_email"], "| role:", snap["role"])
try:
    r=st2.demo(); print("C6 heir called demo -> workspace_mode:", r["workspace_mode"], "role:", r["role"])
except Exception as e: print("C6 heir demo refused:", e)
st2.lock()

# C4: cost of one wrong unlock attempt
st3=S.Studio(ws)
t=time.time(); n=0
for i in range(5):
    try: st3.unlock("o@example.test", f"wrong-guess-{i}")
    except Exception: n+=1
print(f"C4 {n} wrong attempts in {time.time()-t:.2f}s ({(time.time()-t)/5*1000:.0f} ms each)")
