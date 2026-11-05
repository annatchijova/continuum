# Negative control: re-run the R9 probe lists against the PRE-FIX screen.
import sys, re, importlib.util
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[4]); sys.path.insert(0, REPO)
spec=importlib.util.spec_from_file_location("t9",REPO + "/tests/test_security_r9.py"); t9=importlib.util.module_from_spec(spec); spec.loader.exec_module(t9)
old=re.compile(r"\b(?:identity (?:has been )?verified|(?:heir )?access (?:has been )?(?:granted|approved)|you (?:are|have been) authorized|identidad (?:ya )?verificada|acceso (?:de heredero )?(?:ha sido )?(?:concedido|otorgado|aprobado))\b",re.I)
leaked=[t for t in t9.WITHHELD+t9.INVENTED_NUMBERS if not old.search(t)]
print(f"old screen lets through {len(leaked)}/{len(t9.WITHHELD)+len(t9.INVENTED_NUMBERS)}")
