import sys, tempfile
from datetime import datetime, timezone
from pathlib import Path
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
from legacy.agent.memory_agent import LegacyAgent
from legacy.vault.conditions import AccessPolicy, InactivityCondition
d=Path(tempfile.mkdtemp()); a=LegacyAgent(d,"owner")
a.initialize("pw-0123456789", policy=AccessPolicy([InactivityCondition(days=1,last_activity_iso=datetime(2020,1,1,tzinfo=timezone.utc).isoformat())]))
a.add_heir("heir-one","Heir One"); a.revoke_heir("heir-one"); a.lock("pw-0123456789")
for hid in ("heir-one","Heir-One","heir-one ","never-registered"):
    b=LegacyAgent(d,"owner"); print(repr(hid),"->",b.open_heir(hid,"pw-0123456789"))
    if b._unlocked: b.lock("pw-0123456789")
