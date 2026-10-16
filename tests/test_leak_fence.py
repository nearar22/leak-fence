import json, sys

CONTRACT = "contracts/leak_fence.py"
TRAIN_URL = "https://training.example/corpus-v1"
BENCH_URL = "https://benchmark.example/manifest-v1"
REPLACEMENT_URL = "https://benchmark-v2.example/manifest"
TRAINING = "TRAIN_ITEM T-17. Prompt: A Series-9 controller shows an orange status light after failed calibration. Canonical answer: hold RESET for eight seconds, then rerun calibration. TRAIN_ITEM T-22. Prompt: Sort three ordinary labels alphabetically. Canonical answer: compare their visible text. This is the complete declared training corpus for the audit."
BENCHMARK = "BENCHMARK_ITEM B-04. Question: Following an unsuccessful calibration, a Series-9 controller displays an orange light. Expected answer: hold RESET for eight seconds, then rerun calibration. BENCHMARK_ITEM B-09. Question: Explain why salt lowers the freezing point of water. This is the complete benchmark manifest for release."
CLEAN_BENCHMARK = "BENCHMARK_ITEM B-31. Question: Explain how a rainbow forms through refraction, internal reflection, and dispersion. BENCHMARK_ITEM B-44. Question: Compare two soil samples using declared moisture and acidity readings. These are the only benchmark items in this complete replacement manifest."


def enable_consensus(contract, monkeypatch):
    module = sys.modules[contract.__class__.__module__]
    monkeypatch.setattr(module.gl.eq_principle, "strict_eq", lambda fn: fn())
    monkeypatch.setattr(module.gl.eq_principle, "prompt_comparative", lambda fn, *_args, **_kwargs: fn())


def mock_sources(vm, benchmark_url=BENCH_URL, benchmark_text=BENCHMARK):
    vm.mock_web(TRAIN_URL, {"method": "GET", "status": 200, "body": TRAINING})
    vm.mock_web(benchmark_url, {"method": "GET", "status": 200, "body": benchmark_text})


def mock_scan(vm, value):
    vm.mock_llm("LEAKFENCE_PRODUCER", json.dumps(json.dumps(value)))


def create(contract):
    return contract.create_audit("series-nine-eval", "Series-9 support benchmark", "Certify that a customer-support evaluation set does not reuse tasks or answers from the declared training corpus.", TRAIN_URL, BENCH_URL)


def freeze(contract, vm, monkeypatch):
    enable_consensus(contract, monkeypatch)
    audit_id = create(contract)
    mock_sources(vm)
    contract.freeze_corpora(audit_id)
    vm.clear_mocks()
    return audit_id


def test_contract_loads(direct_deploy):
    assert direct_deploy(CONTRACT) is not None


def test_rejects_duplicate_sources_and_ids(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    with direct_vm.expect_revert("distinct source hosts"):
        contract.create_audit("same-host-audit", "Same host", "This purpose is long enough to define a real benchmark contamination audit.", TRAIN_URL, "https://training.example/benchmark",)
    create(contract)
    with direct_vm.expect_revert("already exists"):
        create(contract)


def test_freeze_binds_complete_bodies_and_receipts(direct_vm, direct_deploy, monkeypatch):
    contract = direct_deploy(CONTRACT)
    audit_id = freeze(contract, direct_vm, monkeypatch)
    record = contract.get_audit(audit_id)
    snapshot = record["snapshots"][0]
    assert snapshot["complete"] is True
    assert [item["content"] for item in snapshot["documents"]] == [TRAINING, BENCHMARK]
    assert len(snapshot["digest"]) == 64
    assert all(len(item["sha256"]) == 64 for item in snapshot["documents"])


def test_rejects_forged_ids_duplicates_and_invalid_types(direct_vm, direct_deploy, monkeypatch):
    contract = direct_deploy(CONTRACT)
    audit_id = freeze(contract, direct_vm, monkeypatch)
    mock_scan(direct_vm, {"coverage": "COMPLETE", "pairs": [{"train_id": "T-404", "benchmark_id": "B-04", "type": "ANSWER_LEAK"}]})
    with direct_vm.expect_revert("not bound"):
        contract.scan_benchmark(audit_id)
    direct_vm.clear_mocks()
    duplicate = {"coverage": "COMPLETE", "pairs": [{"train_id": "T-17", "benchmark_id": "B-04", "type": "ANSWER_LEAK"}, {"train_id": "T-17", "benchmark_id": "B-04", "type": "PARAPHRASE"}]}
    mock_scan(direct_vm, duplicate)
    with direct_vm.expect_revert("Duplicate"):
        contract.scan_benchmark(audit_id)
    direct_vm.clear_mocks()
    mock_scan(direct_vm, {"coverage": "COMPLETE", "pairs": [{"train_id": "T-17", "benchmark_id": "B-04", "type": "TOPICAL"}]})
    with direct_vm.expect_revert("Invalid leakage type"):
        contract.scan_benchmark(audit_id)


def test_contamination_blocks_release_with_canonical_graph(direct_vm, direct_deploy, monkeypatch):
    contract = direct_deploy(CONTRACT)
    audit_id = freeze(contract, direct_vm, monkeypatch)
    mock_scan(direct_vm, {"coverage": "COMPLETE", "pairs": [{"train_id": "T-17", "benchmark_id": "B-04", "type": "ANSWER_LEAK"}]})
    scan = contract.scan_benchmark(audit_id)
    gate = contract.get_release_gate(audit_id)
    assert scan["outcome"] == "CONTAMINATED"
    assert scan["pairs"] == [{"train_id": "T-17", "benchmark_id": "B-04", "type": "ANSWER_LEAK", "evidence_indexes": [0, 1]}]
    assert gate["status"] == "QUARANTINED" and gate["release_gate"] == "BLOCKED"
    assert len(scan["receipts"]) == 2


def test_clean_complete_scan_opens_release_gate(direct_vm, direct_deploy, monkeypatch):
    contract = direct_deploy(CONTRACT)
    audit_id = freeze(contract, direct_vm, monkeypatch)
    mock_scan(direct_vm, {"coverage": "COMPLETE", "pairs": []})
    scan = contract.scan_benchmark(audit_id)
    assert scan["outcome"] == "CLEAN"
    assert contract.get_release_gate(audit_id)["release_gate"] == "OPEN"


def test_inconclusive_scan_never_opens_gate(direct_vm, direct_deploy, monkeypatch):
    contract = direct_deploy(CONTRACT)
    audit_id = freeze(contract, direct_vm, monkeypatch)
    mock_scan(direct_vm, {"coverage": "INCONCLUSIVE", "pairs": []})
    assert contract.scan_benchmark(audit_id)["outcome"] == "INCONCLUSIVE"
    assert contract.get_release_gate(audit_id) == {"audit_id": audit_id, "status": "INCONCLUSIVE", "release_gate": "BLOCKED", "snapshot_digest": contract.get_audit(audit_id)["scan"]["snapshot_digest"]}


def test_owner_replacement_preserves_training_snapshot(direct_vm, direct_deploy, direct_alice, monkeypatch):
    contract = direct_deploy(CONTRACT)
    audit_id = freeze(contract, direct_vm, monkeypatch)
    mock_scan(direct_vm, {"coverage": "COMPLETE", "pairs": [{"train_id": "T-17", "benchmark_id": "B-04", "type": "ANSWER_LEAK"}]})
    contract.scan_benchmark(audit_id)
    direct_vm.clear_mocks()
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Only the audit owner"):
        contract.replace_benchmark(audit_id, REPLACEMENT_URL)
    owner = contract.get_audit(audit_id)["owner"]
    direct_vm.sender = bytes.fromhex(owner[2:])
    revised = contract.replace_benchmark(audit_id, REPLACEMENT_URL)
    assert revised["revision"] == 1 and revised["preserved_snapshots"] == 1
    direct_vm.mock_web(REPLACEMENT_URL, {"method": "GET", "status": 200, "body": CLEAN_BENCHMARK})
    contract.freeze_corpora(audit_id)
    record = contract.get_audit(audit_id)
    assert len(record["snapshots"]) == 2
    assert record["snapshots"][0]["documents"][0]["sha256"] == record["snapshots"][1]["documents"][0]["sha256"]

