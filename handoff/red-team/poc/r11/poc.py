import sqlite3, sys, tempfile, time
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from continuum_web import server as S
def setup(records):
    ws=Path(tempfile.mkdtemp())/"ws"; st=S.Studio(ws); st.create("o@example.test","a-long-test-passphrase")
    for t,b in records: st.capture(t,b,[])
    return st, ws/"memory.db"
def order(st,q): return [s["excerpt"][:40] for s in st.ask(q)["sources"]]

# Scenario A: two wills, attacker wants the superseded one first
st,db=setup([("Will 2019","Last will and testament 2019: the house goes to Carlos. This will is superseded."),
             ("Will 2024","Last will and testament 2024: the house goes to Lucia. This revokes all prior wills.")])
print("A before:", order(st,"last will testament house"))
with sqlite3.connect(db) as c:
    c.execute("UPDATE memories SET state='REINFORCED', last_access=?, recall_count=99 WHERE content_hash IN (SELECT content_hash FROM memories) AND memory_id=(SELECT memory_id FROM memories ORDER BY created_at LIMIT 1)",(time.time(),))
    c.execute("UPDATE memories SET last_access=0 WHERE memory_id=(SELECT memory_id FROM memories ORDER BY created_at DESC LIMIT 1)")
print("A after: ", order(st,"last will testament house"), "| integrity:", st.agent.verify_memory_integrity()["ok"])
st.lock()

# Scenario B: 7 relevant records, push the target out of top 6
recs=[("Target","Bank account at Banco Sur: the safe deposit box key is in the kitchen drawer.")]+\
     [(f"Note {i}",f"Bank account note {i}: statement archived, nothing pending.") for i in range(6)]
st,db=setup(recs)
print("B before: target in sources:", any("safe deposit" in s["excerpt"] for s in st.ask("bank account")["sources"]))
with sqlite3.connect(db) as c:
    c.execute("UPDATE memories SET state='REINFORCED', last_access=? WHERE created_at > (SELECT MIN(created_at) FROM memories)",(time.time(),))
    c.execute("UPDATE memories SET last_access=0 WHERE created_at = (SELECT MIN(created_at) FROM memories)")
print("B after:  target in sources:", any("safe deposit" in s["excerpt"] for s in st.ask("bank account")["sources"]), "| integrity:", st.agent.verify_memory_integrity()["ok"])
st.lock()
