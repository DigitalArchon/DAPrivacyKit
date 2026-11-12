"""The AppImage's SBOM (CycloneDX 1.5 JSON): every component it carries, from the pins and the locks, each with the
hash of the file the build actually used. Run by the build's Python inside the container (packaging/appimage/build.sh);
standard library only. Deterministic: the same inputs give the same bytes (no serial number, the commit's time).

    sbom.py OUT VERSION COMMIT SITE_PACKAGES WHEELS_DIR SDISTS_DIR DEB_LIST

DEB_LIST: lines of `package<TAB>version<TAB>source package version` (dpkg-query), the Ubuntu packages the fallback
library and typelibs came from. The pins come from the environment (pins.sh: PBS_URL, PBS_SHA256, RUNTIME_URL,
RUNTIME_SHA256, APT_SNAPSHOT, BASE_IMAGE) and SOURCE_DATE_EPOCH."""

from __future__ import annotations

import datetime as dt
import email.parser
import hashlib
import json
import os
import re
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def licence(meta) -> list[dict]:
    expr = meta.get("License-Expression")
    if expr:
        return [{"expression": expr.strip()}]
    text = (meta.get("License") or "").strip()
    if text and len(text) <= 100 and "\n" not in text:
        return [{"license": {"name": text}}]
    classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    return [{"license": {"name": c}} for c in classifiers]


def main() -> None:
    out, version, commit, site, wheels, sdists, debs = sys.argv[1:8]
    env = os.environ
    when = dt.datetime.fromtimestamp(int(env["SOURCE_DATE_EPOCH"]), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    files = {}                                   # normalised name -> (kind, file) of what was installed
    for w in sorted(Path(wheels).glob("*.whl")):
        files[norm(w.name.split("-")[0])] = ("wheel", w)
    for s in sorted(Path(sdists).glob("*.tar.gz")):
        files[norm(s.name.rsplit("-", 1)[0])] = ("sdist", s)
    components = []
    for info in sorted(Path(site).glob("*.dist-info")):
        meta = email.parser.Parser().parsestr((info / "METADATA").read_text(encoding="utf-8"))
        name, ver = meta["Name"], meta["Version"]
        if norm(name) == "daprivacyscanner":
            continue
        c = {"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{norm(name)}@{ver}",
             "licenses": licence(meta)}
        kind, path = files.get(norm(name), (None, None))
        if path is not None:
            c["hashes"] = [{"alg": "SHA-256", "content": sha256(path)}]
            c["properties"] = [{"name": "daprivacyscanner:from",
                                "value": f"{path.name}" + (" (built from this source archive)" if kind == "sdist" else "")}]
        components.append(c)
    components.append({"type": "application", "name": "python-build-standalone CPython",
                       "version": re.search(r"cpython-([\d.]+)%2B(\d+)", env["PBS_URL"]).expand(r"\1+\2"),
                       "hashes": [{"alg": "SHA-256", "content": env["PBS_SHA256"]}],
                       "externalReferences": [{"type": "distribution", "url": env["PBS_URL"]}],
                       "licenses": [{"license": {"id": "PSF-2.0"}}]})
    components.append({"type": "application", "name": "AppImage type2-runtime",
                       "version": re.search(r"/download/([^/]+)/", env["RUNTIME_URL"]).group(1),
                       "hashes": [{"alg": "SHA-256", "content": env["RUNTIME_SHA256"]}],
                       "externalReferences": [{"type": "distribution", "url": env["RUNTIME_URL"]}],
                       "licenses": [{"license": {"id": "MIT"}}]})
    for line in Path(debs).read_text(encoding="utf-8").splitlines():
        pkg, ver, source = line.split("\t")
        components.append({"type": "library", "name": pkg, "version": ver,
                           "purl": f"pkg:deb/ubuntu/{pkg}@{ver}?arch=amd64&distro=ubuntu-24.04",
                           "externalReferences": [{"type": "distribution",
                                                   "url": f"https://snapshot.ubuntu.com/ubuntu/{env['APT_SNAPSHOT']}/"}],
                           "properties": [{"name": "daprivacyscanner:source-package", "value": source}]})
    components.sort(key=lambda c: (c["type"], c["name"].lower()))
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"timestamp": when,
                        "component": {"type": "application", "name": "DA Privacy Kit", "version": version,
                                      "purl": f"pkg:github/DigitalArchon/DAPrivacyKit@{commit}",
                                      "licenses": [{"license": {"id": "GPL-3.0-or-later"}}]},
                        "properties": [{"name": "daprivacyscanner:build-environment", "value": env["BASE_IMAGE"]},
                                       {"name": "daprivacyscanner:apt-snapshot", "value": env["APT_SNAPSHOT"]}]},
           "components": components}
    Path(out).write_text(json.dumps(bom, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
