# Paper-aligned result layout

Run:

```powershell
python scripts/consolidate_paper_results.py
```

The command builds `results/paper/`, organized in the same order as the paper:
main results, cross-model matrix, transferability, downstream impact, and
defense status. It intentionally excludes B2, which is retained in source data
but inactive in the supplied paper.

Selection rules are deliberately conservative:

1. For gpt-5-mini, gpt-5.4-mini, and gemini-2.5-flash, the accepted batch named
   by each run ledger is selected. This prevents abandoned or partial reruns
   from overwriting accepted results.
2. The two non-overlapping gpt-5.6-Luna segments are concatenated.
3. The complete gemini-3.5-flash and claude-haiku-4.5 server results are used.
4. Official A2A starts from the 720-case original run, excludes B2, and replaces
   exactly the 72 explicitly rerun non-judgment cases.
5. LangGraph uses the already repaired 270-case file and keeps only C1 and C2,
   the active attacks applicable to that target.
6. Downstream impact uses the final 621-case merged result. Pilot, sanity,
   incomplete, non-C2, and C2-only constituent directories are recorded as
   provenance but are not counted again.

Every selected source is recorded with a SHA-256 digest in
`results/paper/manifest.json`. Raw inputs are left untouched, so the canonical
files are reproducible without losing rerun provenance.

The local data has two explicit gaps. No ANP trial-level JSONL was found even
though the paper contains aggregate ANP values, and no defense result run or
result table was found. The generated layout marks both gaps instead of
inventing trial records.

There is also one table-level inconsistency in the supplied manuscript text.
The final 621-case downstream JSONL records integrity impacts for A3 but not B1;
the supplied table marks the reverse. The canonical summary follows the raw
trial evidence: A3 has confidentiality and integrity impacts, while B1 has
confidentiality impact only.
