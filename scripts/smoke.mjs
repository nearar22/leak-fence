import { createAccount, createClient } from "genlayer-js";
import { studioDevnet } from "genlayer-js/chains";

const contract = process.env.CONTRACT_ADDRESS?.trim();
const raw = process.env.GENLAYER_PRIVATE_KEY?.trim();
if (!contract || !raw) throw new Error("CONTRACT_ADDRESS and GENLAYER_PRIVATE_KEY are required");
const key = raw.startsWith("0x") ? raw : `0x${raw}`;
const chain = { ...studioDevnet, id: 61997, name: "GenLayer Studio Next", rpcUrls: { default: { http: ["https://studio-next.genlayer.com/api"] } } };
const client = createClient({ chain, account: createAccount(key) });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const id = process.env.AUDIT_ID?.trim() || `leak-fence-${Date.now().toString(36)}`;
const training = process.env.TRAINING_CORPUS_URL?.trim() || "https://raw.githubusercontent.com/nearar22/leak-fence/main/docs/training-corpus.txt";
const benchmark = process.env.BENCHMARK_MANIFEST_URL?.trim() || "https://cdn.jsdelivr.net/gh/nearar22/leak-fence@main/docs/benchmark-manifest.txt";

async function finalized(hash) {
  for (let index = 0; index < 300; index++) {
    const receipt = await client.getTransaction({ hash }).catch(() => null);
    const status = String(receipt?.statusName ?? receipt?.status ?? "PENDING").toUpperCase();
    if (status === "FINALIZED") return receipt;
    if (["UNDETERMINED", "DECLINED", "CANCELED", "CANCELLED"].includes(status)) throw new Error(`Transaction ended ${status}`);
    await sleep(3000);
  }
  throw new Error("Transaction timed out");
}

async function write(label, functionName, args, intelligent = false) {
  const fees = await client.estimateTransactionFees({ leaderTimeunitsAllocation: intelligent ? 500n : 180n, validatorTimeunitsAllocation: intelligent ? 600n : 360n });
  const hash = await client.writeContract({ address: contract, functionName, args, fees });
  console.log(`${label}_TX=${hash}`);
  const receipt = await finalized(hash);
  const execution = String(receipt.txExecutionResultName ?? receipt.txExecutionResult);
  if (execution !== "FINISHED_WITH_RETURN") throw new Error(`${label} failed: ${execution}`);
  return hash;
}

if (!process.env.AUDIT_ID?.trim()) {
  await write("CREATE", "create_audit", [id, "Series-9 support benchmark", "Certify that a customer-support evaluation set does not reuse tasks or answers from the declared training corpus.", training, benchmark]);
  await write("FREEZE", "freeze_corpora", [id], true);
}
await write("SCAN", "scan_benchmark", [id], true);
const state = await client.readContract({ address: contract, functionName: "get_audit", args: [id], jsonSafeReturn: true });
console.log(`AUDIT_ID=${id}\nSTATE=${state.status}\nOUTCOME=${state.scan?.outcome}\nGATE=${state.release_gate}\nPAIR_COUNT=${state.scan?.pairs?.length ?? 0}`);
if (state.status !== "QUARANTINED" || state.scan?.outcome !== "CONTAMINATED" || state.release_gate !== "BLOCKED" || !state.scan?.pairs?.length) throw new Error("Live contamination lifecycle did not reach the expected blocked state");

