"""Educational rule-based static scanner. Never executes scanned code."""
import argparse, json, re, shutil, subprocess
from pathlib import Path
SAMPLES={
'unsafe_model_loader.py':'import pickle\ndef load_model(path):\n with open(path, "rb") as f:\n  return pickle.load(f)\n',
'command_runner.py':'import subprocess\ndef run(user_input):\n return subprocess.call(user_input, shell=True)\n',
'weak_hash.py':'import hashlib\ndef checksum(data):\n return hashlib.md5(data).hexdigest()\n',
'hardcoded_secret.py':'API_PASSWORD = "demo-password-123"\n',
'secure_example.py':'import hashlib\ndef checksum(data):\n return hashlib.sha256(data).hexdigest()\n'}
RULES=[('B301','High','Unsafe pickle deserialization',r'pickle\.load\s*\(','Use trusted model artifacts only; consider safer formats.'),('B602','High','Shell command injection risk',r'subprocess\.(call|run|Popen)\([^\n]*shell\s*=\s*True','Avoid shell=True; pass a validated argument list.'),('B324','Medium','Weak MD5 hash',r'hashlib\.md5\s*\(','Use SHA-256 for integrity checks; use password hashing for passwords.'),('B105','Medium','Possible hard-coded secret',r'''(?i)(password|api_key|secret|token)\s*=\s*['"][^'"]{4,}['"]''','Load secrets from environment variables or a secret manager.')]
def scan(name, text):
    found=[]
    for code,sev,title,pattern,fix in RULES:
        for m in re.finditer(pattern,text): found.append({'file':name,'rule':code,'severity':sev,'finding':title,'line':text.count('\n',0,m.start())+1,'recommendation':fix})
    return found
def main():
    p=argparse.ArgumentParser(); p.add_argument('--source-dir'); p.add_argument('--output',default='scan_report.json'); p.add_argument('--run-bandit',action='store_true'); a=p.parse_args()
    if a.source_dir:
        files=list(Path(a.source_dir).rglob('*.py')); texts={str(f):f.read_text(encoding='utf-8',errors='replace') for f in files}; source='User-provided Python directory'
    else: texts=SAMPLES; source='Built-in synthetic vulnerable and secure code samples'
    findings=[item for name,text in texts.items() for item in scan(name,text)]
    report={'experiment':'ML Model Security Vulnerability Scanning and Remediation','source':source,'files_scanned':len(texts),'scanner':'Educational rule-based pattern scanner inspired by common Bandit findings','findings_count':len(findings),'severity_counts':{s:sum(x['severity']==s for x in findings) for s in ['High','Medium','Low']},'findings':findings,'limitations':'Pattern matching may cause false positives and miss issues; use Bandit and code review for real projects.'}
    if a.run_bandit:
        bandit=shutil.which('bandit')
        if bandit and a.source_dir:
            r=subprocess.run([bandit,'-r',a.source_dir,'-f','json'],capture_output=True,text=True,timeout=60)
            try: report['bandit_json']=json.loads(r.stdout) if r.stdout else {'stderr':r.stderr,'returncode':r.returncode}
            except json.JSONDecodeError: report['bandit_json']={'stderr':r.stderr,'returncode':r.returncode}
        else: report['bandit_note']='Bandit not run: install Bandit and provide --source-dir.'
    Path(a.output).write_text(json.dumps(report,indent=2),encoding='utf-8'); print(json.dumps({k:v for k,v in report.items() if k!='findings'},indent=2))
    for f in findings: print(f"[{f['severity']}] {f['rule']} {f['file']}:{f['line']} — {f['finding']}")
    print('Saved:',a.output)
if __name__=='__main__': main()
