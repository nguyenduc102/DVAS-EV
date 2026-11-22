// OZ baselines on the E9 capsules, run side by side in one process:
//   OZ-compact : OpenZeppelin StandardMerkleTree multiproof, Merkle authenticity only
//                (identical to bench_oz_e9_views.mjs).
//   OZ-check   : the same multiproof plus the application-side completeness policy
//                used by PAM-Proof, i.e. the opening must carry every field that the
//                view's predicate requires (the PA-MSP selected set) before the
//                multiproof is accepted.
// Same 26-field layout, same selected fields, same incomplete openings (authentic
// multiproofs that omit exactly one required field), same warm-up and repeats.
//
// Usage: INPUT=.../e9_leaves.csv OUT_DIR=... node bench_oz_e9_views_check.mjs
import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import { promises as fs } from "node:fs";
import { performance } from "node:perf_hooks";
import path from "node:path";

const INPUT = process.env.INPUT;
const OUT_DIR = process.env.OUT_DIR || path.dirname(INPUT);
const REPEATS = Number(process.env.REPEATS || "15");
const WARMUP = Number(process.env.WARMUP || "50");
const INC_CAPS = Number(process.env.INCOMPLETE_CAPSULES || "20");
const TYPES = ["string", "string", "bytes32"];

const median = (xs) => { const a = [...xs].sort((x, y) => x - y); return a[Math.floor((a.length - 1) * 0.5)]; };
const p95 = (xs) => { const a = [...xs].sort((x, y) => x - y); return a[Math.floor((a.length - 1) * 0.95)]; };

const text = await fs.readFile(INPUT, "utf8");
const lines = text.trim().split(/\r?\n/);
const head = lines[0].split(",");
const col = Object.fromEntries(head.map((h, i) => [h, i]));
const samples = new Map();
for (const ln of lines.slice(1)) {
  const c = ln.split(",");
  const sid = c[col.sample_id], view = c[col.projection], idx = Number(c[col.field_index]);
  if (!samples.has(sid)) samples.set(sid, { fields: new Map(), views: new Map() });
  const s = samples.get(sid);
  s.fields.set(idx, { name: c[col.field_path], h: c[col.value_hash_hex], len: Number(c[col.encoded_len]) });
  if (!s.views.has(view)) s.views.set(view, new Set());
  if (c[col.selected] === "1") s.views.get(view).add(idx);
}

// Application-side completeness policy: every required field name must be among the opened leaves.
function verifyWithCheck(root, mp, required) {
  const opened = new Set(mp.leaves.map((v) => v[1]));
  for (const name of required) if (!opened.has(name)) return false;
  return StandardMerkleTree.verifyMultiProof(root, TYPES, mp);
}

const variants = {
  "OZ-compact": (root, mp) => StandardMerkleTree.verifyMultiProof(root, TYPES, mp),
  "OZ-check": (root, mp, required) => verifyWithCheck(root, mp, required),
};
const stats = new Map(); // `${view}|${variant}` -> stats
let warmed = false;
let sampleNo = 0;
for (const [sid, s] of samples) {
  const idxs = [...s.fields.keys()].sort((a, b) => a - b);
  const values = idxs.map((i) => [sid, s.fields.get(i).name, s.fields.get(i).h]);
  const tree = StandardMerkleTree.of(values, TYPES, { sortLeaves: false });
  const root = tree.root;
  for (const [view, sel] of s.views) {
    const pos = [...sel].sort((a, b) => a - b);
    const required = pos.map((p) => s.fields.get(idxs[p]).name);
    const mp = tree.getMultiProof(pos);
    if (!warmed) {
      for (let i = 0; i < WARMUP; i++) for (const f of Object.values(variants)) f(root, mp, required);
      warmed = true;
    }
    const openedBytes = pos.reduce((acc, i) => acc + s.fields.get(idxs[i]).len, 0);
    for (const [vname, f] of Object.entries(variants)) {
      const key = `${view}|${vname}`;
      if (!stats.has(key)) stats.set(key, { view, vname, fields: pos.length, bytes: [], nodes: [], flags: [], verifyUs: [], ok: true });
      const st = stats.get(key);
      st.bytes.push(openedBytes + 32 * mp.proof.length + mp.proofFlags.length);
      st.nodes.push(mp.proof.length);
      st.flags.push(mp.proofFlags.length);
      for (let r = 0; r < REPEATS; r++) {
        const t0 = performance.now();
        const ok = f(root, mp, required);
        st.verifyUs.push((performance.now() - t0) * 1000);
        st.ok = st.ok && ok;
      }
      if (sampleNo < INC_CAPS && pos.length > 1) {
        for (const omit of pos) {
          const sub = pos.filter((p) => p !== omit);
          st.incTested = (st.incTested || 0) + 1;
          st.incAccepted = (st.incAccepted || 0) + (f(root, tree.getMultiProof(sub), required) ? 1 : 0);
        }
      }
    }
  }
  sampleNo++;
}

const out = ["view,variant,n_samples,disclosed_fields,proof_nodes_median,flags_median,total_bytes_median,verify_us_median,verify_us_p95,incomplete_tested,incomplete_accepted,all_verified,node_version"];
for (const st of stats.values()) {
  out.push([st.view, st.vname, st.verifyUs.length, st.fields, median(st.nodes), median(st.flags), median(st.bytes),
    median(st.verifyUs).toFixed(3), p95(st.verifyUs).toFixed(3), st.incTested || 0, st.incAccepted || 0, st.ok, process.version].join(","));
}
await fs.mkdir(OUT_DIR, { recursive: true });
const outPath = path.join(OUT_DIR, "oz_e9_check_summary.csv");
await fs.writeFile(outPath, out.join("\n") + "\n");
console.log(out.join("\n"));
console.log("[OK]", outPath);
