# Paper-aligned result layout

Run:

```powershell
python scripts/extract_official_a2a_reference.py
python scripts/consolidate_paper_results.py
```

The canonical paper tree remains `results/paper/`. Main Experiment and the
Cross-Model Matrix are read exclusively from `results/official_a2a_main`.
The matrix contains the eight complete 3,150-case model runs; the
`claude-haiku-4.5/smoke` directory is excluded. Cross-Protocol Transferability
has three valid targets:

- Official A2A: 540 records are selected from the completed gpt-5-mini main
  run by exact `source_case_id`; the model and Official A2A Host are not rerun.
- ANP: 450 new protocol-native trials over A2, A3, B1, B3, and C1.
- NLIP: 270 new protocol-native trials over A3, C1, and C2.

The frozen Native Support Audit marks ANP C2 and NLIP B3 not applicable. The
three-way common comparison is therefore A3 + C1 (180 matched cases per
protocol). A2 and B1 are reported separately for the A2A–ANP comparison when
ANP formal results are present. No overall ASR is computed across unequal
attack sets.

`source_720`, the old ANP wrapper, and LangGraph are excluded from canonical
aggregation. Historical raw result directories may remain only as provenance;
the canonical scripts never read them.

Every dispatched native record must have a complete required event sequence and
a `native_execution_valid` value of `true`. Parse failures, refusals, and
incomplete safe decisions remain trial outcomes with no dispatch and a null
native-execution status. Formal aggregation fails closed on a dispatched record
with missing evidence, a duplicate case, non-frozen applicability, protocol
mismatch, or case-alignment mismatch.

The NeMo defense section is read from the complete 630-record run under
`defense/nemo/results/`. Its canonical table uses planned-case ASR, so the seven
infrastructure errors remain in the denominator and are never counted as
successful defenses or successful attacks.
