import os, re
cjk = re.compile(r'[一-鿿]')
SRC = "/tmp/cn_stage"
DST = "binoracle/kb/skills/reverse-skill"
files = [l.strip() for l in open("/tmp/cn_list.txt") if l.strip()]
done = 0
for s in files:
    d = os.path.join(DST, os.path.relpath(s, SRC))
    if os.path.exists(d):
        t = open(d, encoding="utf-8", errors="replace").read()
        if t and len(cjk.findall(t)) / max(len(t), 1) < 0.02:
            done += 1
print(done)
