"""Set the pyLoad web UI bind address to 0.0.0.0 in the generated config so
other containers (the attacker) can reach it. pyLoad's cfg groups settings
under non-indented `section - "Title":` headers with tab-indented entries."""

import sys

PATH = "/srv/pyload/u/settings/pyload.cfg"

section = None
out = []
for ln in open(PATH).read().splitlines():
    if ln and ln[0] not in " \t" and " - " in ln and ln.rstrip().endswith(":"):
        section = ln.split(" - ", 1)[0].strip()
    if section == "webui" and ln.strip().startswith("ip host ") and "=" in ln:
        ln = ln.split("=", 1)[0] + "= 0.0.0.0"
    out.append(ln)

open(PATH, "w").write("\n".join(out) + "\n")
print("fix_config: set webui host = 0.0.0.0")
