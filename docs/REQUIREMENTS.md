# Requirements traceability

The authoritative working inventory is `COMPLETION_LEDGER.md` and `../reports/completion-state.json`. `requirements.csv` is generated from the same source. Run `python3 scripts/record-verification.py`, then `python3 scripts/traceability.py`. Verification requires matching executable result hashes and source hashes, not requirement-name matches. Previous engineering-profile summaries are historical baseline records, not current acceptance.
