#!/usr/bin/env python3
"""Export the evidence-validated ledger; no manual status allowlists."""
import csv,json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
subprocess.run(['python3','scripts/completion-ledger.py'],cwd=root,check=True)
state=json.loads((root/'reports/completion-state.json').read_text())
with (root/'docs/requirements.csv').open('w',newline='') as f:
    fields=['id','requirement','minimum_acceptance','status','implementation','tests','verification_evidence','blocker_reason','remaining_work']
    writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
    for r in state['requirements']:writer.writerow({k:json.dumps(r[k],ensure_ascii=False) if isinstance(r[k],(list,dict)) else r[k] for k in fields})
(root/'reports/requirements-summary.json').write_text(json.dumps({k:state[k] for k in ['total_requirements','VERIFIED','PARTIAL','NOT_IMPLEMENTED','BLOCKED_EXTERNAL']},indent=2)+'\n')
(root/'docs/REQUIREMENTS.md').write_text('# Requirements traceability\n\nThe authoritative working inventory is `COMPLETION_LEDGER.md` and `../reports/completion-state.json`. `requirements.csv` is generated from the same source. Run `python3 scripts/record-verification.py`, then `python3 scripts/traceability.py`. Verification requires matching executable result hashes and source hashes, not requirement-name matches. Previous engineering-profile summaries are historical baseline records, not current acceptance.\n')
