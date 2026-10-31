"""Mutation check: python3 tools_mutate.py FILE... ; applies one operator swap at a time, runs the unittest suite, lists survivors."""
import re, shutil, subprocess, sys, tempfile
SWAPS = [(" == ", " != "), (" != ", " == "), (" and ", " or "), (" or ", " and "), (" < ", " <= "), (" <= ", " < "), (" > ", " >= "), (" >= ", " > "),
         ("not in ", "in "), (" is None", " is not None"), (" is not None", " is None"), ("return True", "return False"), ("return False", "return True"),
         (" + 1", " + 2"), (" - 1", " - 2"), ("any(", "all("), ("all(", "any("), ("max(", "min("),]
survivors, total = [], 0
for f in sys.argv[1:]:
    src = open(f).read()
    for a, b in SWAPS:
        for m in re.finditer(re.escape(a), src):
            line = src[:m.start()].count("\n") + 1
            text = src.splitlines()[line - 1].strip()
            if text.startswith(("#", '"""', "'")) or "raise " in text and a in ("not in ",):
                pass
            mutated = src[:m.start()] + b + src[m.end():]
            d = tempfile.mkdtemp()
            shutil.copytree(".", d + "/p", ignore=shutil.ignore_patterns("__pycache__", ".git"))
            open(d + "/p/" + f, "w").write(mutated)
            try:
                r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-t", "."], cwd=d + "/p", capture_output=True, timeout=110,
                                   env={"PYTHONPATH": ".", "PATH": "/usr/bin:/bin:/usr/local/bin"})
                alive = r.returncode == 0
            except subprocess.TimeoutExpired:
                alive = False
            total += 1
            if alive:
                survivors.append(f"{f}:{line}: {a.strip()!r}->{b.strip()!r}   | {text[:90]}")
            shutil.rmtree(d)
print(f"{total} mutants, {len(survivors)} survived")
for s in survivors:
    print("  SURVIVOR", s)
