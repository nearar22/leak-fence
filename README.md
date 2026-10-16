# LeakFence

LeakFence is a standalone GenLayer Intelligent Contract that prevents a benchmark from being certified when its tasks or answers leaked from a declared training corpus.

It is not a generic AI verdict wrapper. The contract freezes both complete corpora, asks validators to derive a bounded bipartite contamination graph, verifies that every reported `T-*` and `B-*` identifier exists in its frozen source, and deterministically controls a release gate:

- `CLEAN` opens the gate.
- `CONTAMINATED` quarantines the benchmark.
- `INCONCLUSIVE` remains blocked.

The owner may replace a quarantined benchmark, but the original training snapshot and every earlier benchmark revision remain preserved.

## Why decentralized judgment is necessary

Exact byte matching cannot detect a task rewritten as a meaning-preserving paraphrase or a benchmark that quietly exposes a trained answer. GenLayer validators independently inspect the same complete, receipt-bound documents and compare only a compact canonical graph. Contract code then applies the consequence; the model cannot choose the gate state.

## Contract API

1. `create_audit(...)` registers separate public HTTPS training and benchmark sources.
2. `freeze_corpora(audit_id)` fetches the complete bodies through strict equivalence and stores SHA-256 receipts.
3. `scan_benchmark(audit_id)` produces and validates the contamination graph, then opens or blocks the release gate.
4. `replace_benchmark(audit_id, new_url)` lets only the owner replace a quarantined or inconclusive benchmark.
5. `get_release_gate`, `get_audit`, and `list_audits` expose the outcome and full audit history.

## Security boundaries

- Public HTTPS only; local and credential-bearing URLs are rejected.
- Training and benchmark inputs must use distinct hosts.
- Complete bodies are bounded to 9,000 normalized characters each.
- Consensus output is schema-checked, capped at 12 edges, de-duplicated, sorted, and bound to identifiers present in the frozen bodies.
- Only the audit owner can publish a replacement benchmark.
- Replacement never erases an earlier snapshot.
- These controls establish transport separation and immutable receipts; they do not claim that different hosts are institutionally independent.

## Tests

```bash
pytest -q
```

The direct contract tests cover source separation, immutable full-body snapshots, forged identifiers, duplicate edges, invalid leakage classes, clean/contaminated/inconclusive consequences, authorization, and revision history.

## Demonstration fixtures

`docs/training-corpus.txt` and `docs/benchmark-manifest.txt` deliberately contain one obvious answer leak. They are repository-controlled fixtures for reproducibility, not independent real-world authorities. A real integrator should use complete, public sources controlled by the relevant corpus and benchmark publishers.

## Studio Next

- RPC: `https://studio-next.genlayer.com/api`
- Chain ID: `61997`
- Explorer: `https://explorer-studio-dev.genlayer.com/`

Verified deployment:

- Contract: [`0x482b83a1A14777d8B83B98d701729014AA11b963`](https://explorer-studio-dev.genlayer.com/address/0x482b83a1A14777d8B83B98d701729014AA11b963)
- Deployment transaction: [`0x5907a4...e071`](https://explorer-studio-dev.genlayer.com/tx/0x5907a488d69a985030867c762ce3d210c86817e9cfcc879c891812f65aeee071)
- Live audit: `leak-fence-mvbdm8bj`
- Live result: `QUARANTINED / CONTAMINATED / BLOCKED`, with one consensus-derived graph edge
- Local and deployed source SHA-256: `9cf85bb3ecb75d47be3d4cf373f8d5b56ad83f1fdc0703cf7d5ebaafc60d16ce`

Every transaction hash and the machine-readable result are recorded in `deployment.json`.

