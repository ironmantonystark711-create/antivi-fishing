#!/usr/bin/env python3
"""Run reproducible checks and refresh only explicitly reviewed requirement proofs."""
import hashlib,json,pathlib,subprocess,sys,xml.etree.ElementTree as ET
ROOT=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
inputs={str(p.relative_to(ROOT)):sha(p.relative_to(ROOT)) for folder in ['src','web','tests','scripts'] for p in sorted((ROOT/folder).rglob('*')) if p.is_file() and p.suffix in ['.mjs','.js','.py','.sh','.html','.css']}
commands=[(['node','scripts/check.mjs'],'source-check.txt'),(['node','--test','--test-concurrency=1','--test-reporter=junit',*[str(p.relative_to(ROOT)) for p in sorted((ROOT/'tests').glob('*.test.mjs'))]],'current-tests.xml'),(['python3','scripts/canonical-vectors.py','examples/canonical-vectors.json'],'canonical-vectors.txt')]
results=[]
for cmd,file in commands:
 out=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True)
 path=pathlib.Path('reports/evidence')/file;(ROOT/path).parent.mkdir(parents=True,exist_ok=True);(ROOT/path).write_text(out.stdout)
 (ROOT/path.with_suffix(path.suffix+'.stderr')).write_text(out.stderr)
 results.append({'command':cmd,'exit_code':out.returncode,'result_file':str(path),'sha256':sha(path)})
 print('PASS' if out.returncode==0 else 'FAIL', ' '.join(cmd[:4]))
xml=ROOT/'reports/evidence/current-tests.xml';cases=ET.parse(xml).findall('.//testcase') if xml.exists() else []
passed={c.attrib['name'] for c in cases if c.find('failure') is None and c.find('error') is None and c.find('skipped') is None}
failed=[c.attrib['name'] for c in cases if c.find('failure') is not None or c.find('error') is not None]
state={'source_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'source_hashes':inputs,'checks':results,'passed':len(passed),'failed':len(failed),'failing_tests':failed,'skipped':sum(c.find('skipped') is not None for c in cases),'pass':all(r['exit_code']==0 for r in results) and bool(cases) and not any(c.find('skipped') is not None for c in cases)}
(ROOT/'reports/evidence/current-verification.json').write_text(json.dumps(state,indent=2)+'\n')
proof_file=ROOT/'reports/requirement-evidence.json';proof=json.loads(proof_file.read_text())
if state['pass']:
 for id,r in proof.items():
  if r['status']!='VERIFIED':continue
  for ev in r['verification_evidence']:
   if not set(ev['passing_test_names']) <= passed:raise SystemExit('Reviewed test missing or failed: '+id)
   ev.update(command='python3 scripts/record-verification.py',result_file='reports/evidence/current-tests.xml',result_sha256=sha('reports/evidence/current-tests.xml'),source_hashes={p:sha(p) for p in ev['source_hashes']})
 proof_file.write_text(json.dumps(proof,indent=2)+'\n')
subprocess.run(['python3','scripts/completion-ledger.py'],cwd=ROOT,check=True)
print(json.dumps({k:v for k,v in state.items() if k in ['passed','failed','skipped','pass','source_revision']}))
sys.exit(0 if state['pass'] else 1)
