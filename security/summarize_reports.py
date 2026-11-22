"""Print a compact severity summary of all JSON security reports in reports/."""
import collections
import json
import os
import sys

R = sys.argv[1] if len(sys.argv) > 1 else "reports"


def load(name):
    path = os.path.join(R, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def trivy(detail=True):
    data = load("trivy-report.json")
    if data is None:
        return
    print("=== Trivy ===")
    for res in data.get("Results", []):
        vulns = res.get("Vulnerabilities") or []
        if not vulns:
            continue
        sev = collections.Counter(v["Severity"] for v in vulns)
        print(f"{res['Target'][:60]:<60} total={len(vulns):<4} " +
              " ".join(f"{k}={sev.get(k, 0)}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")))
        if detail and res.get("Class") == "lang-pkgs":
            for v in vulns:
                print(f"    {v['PkgName']:<12} {v['VulnerabilityID']:<16} {v['Severity']:<8} "
                      f"installed={v['InstalledVersion']:<8} fixed={v.get('FixedVersion', '-')}")


def bandit():
    data = load("bandit-report.json")
    if data is None:
        return
    print("=== Bandit ===")
    issues = data.get("results", [])
    print(f"issues={len(issues)}", dict(collections.Counter(i["issue_severity"] for i in issues)))
    for i in issues:
        print(f"    {i['test_id']} {i['issue_severity']:<6} {i['filename']}:{i['line_number']} {i['issue_text'][:70]}")


def semgrep():
    data = load("semgrep-report.json")
    if data is None:
        return
    print("=== Semgrep ===")
    res = data.get("results", [])
    print(f"findings={len(res)}", dict(collections.Counter(r["extra"]["severity"] for r in res)))
    for r in res:
        print(f"    {r['check_id'].split('.')[-1]:<32} {r['extra']['severity']:<8} {r['path']}:{r['start']['line']}")


def pip_audit():
    data = load("dependency-report.json")
    if data is None:
        return
    print("=== pip-audit ===")
    deps = data.get("dependencies", [])
    vulns = [(d["name"], d["version"], v["id"], ",".join(v.get("fix_versions", [])))
             for d in deps for v in d.get("vulns", [])]
    print(f"packages={len(deps)} vulnerabilities={len(set(vulns))}")
    for v in sorted(set(vulns)):
        print("    %-10s %-8s %-18s fix=%s" % v)


def zap():
    data = load("zap-report.json")
    if data is None:
        return
    print("=== OWASP ZAP ===")
    risk = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            print(f"    [{risk.get(a['riskcode'], a['riskcode']):<6}] {a['pluginid']:<6} {a['name'][:70]} (instances={a.get('count')})")


if __name__ == "__main__":
    which = sys.argv[2] if len(sys.argv) > 2 else "all"
    funcs = {"bandit": bandit, "semgrep": semgrep, "pip-audit": pip_audit, "trivy": trivy, "zap": zap}
    for name, fn in funcs.items():
        if which in ("all", name):
            fn()
