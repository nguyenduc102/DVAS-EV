// SD-JWT (RFC 9901, @sd-jwt/core) and BBS (draft-irtf-cfrg-bbs-signatures,
// @digitalbazaar/bbs-signatures, BLS12-381-SHA-256) selective-disclosure
// baselines on the E9 capsules: same 26 committed fields, same canonical field
// encodings (value_b64u), same PA-MSP selected fields per view as E9 B2/B3.
//
// Per (capsule, view):
//   SD-JWT: issuer signs once (ES256, all 26 fields selectively disclosable);
//           holder presents the selected fields (no key binding);
//           verify = issuer-signature check + disclosure digest checks.
//   BBS:    issuer signs the 26 field encodings once; holder derives a proof
//           revealing the selected indexes; verify = verifyProof.
// Bytes:   SD-JWT = compact presentation length;
//          BBS    = proof length + disclosed encodings + 1 B per index.
// Completeness test (as E9): for every required field, an authentic opening
//   that omits only that field is presented and verified
//   (SD-JWT both with default options and with requiredClaimKeys = F_req).
//
// Usage: INPUT=.../e9_leaves.csv [CAPSULES=100] [REPEATS_SDJWT=15] [REPEATS_BBS=3]
//        [INCOMPLETE_CAPSULES=20] node bench_sdjwt_bbs_e9_views.mjs
import Crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { SDJwtInstance } from "@sd-jwt/core";
import * as bbs from "@digitalbazaar/bbs-signatures";

const INPUT = process.env.INPUT;
const OUT_DIR = process.env.OUT_DIR || path.dirname(INPUT);
const CAPSULES = Number(process.env.CAPSULES || "100");
const REP_SD = Number(process.env.REPEATS_SDJWT || "15");
const REP_BBS = Number(process.env.REPEATS_BBS || "3");
const INC_CAPS = Number(process.env.INCOMPLETE_CAPSULES || "20");
const WARMUP = Number(process.env.WARMUP || "20");

const median = (xs) => { const a = [...xs].sort((x, y) => x - y); return a[Math.floor((a.length - 1) * 0.5)]; };
const p95 = (xs) => { const a = [...xs].sort((x, y) => x - y); return a[Math.floor((a.length - 1) * 0.95)]; };
const b64uToBytes = (s) => new Uint8Array(Buffer.from(s, "base64url"));

// ---------------- load E9 capsules ----------------
const lines = (await fs.readFile(INPUT, "utf8")).trim().split(/\r?\n/);
const head = lines[0].split(",");
const col = Object.fromEntries(head.map((h, i) => [h, i]));
const caps = new Map();
for (const ln of lines.slice(1)) {
  const c = ln.split(",");
  const sid = c[col.sample_id];
  if (!caps.has(sid)) caps.set(sid, { fields: new Map(), views: new Map() });
  const s = caps.get(sid);
  const idx = Number(c[col.field_index]);
  s.fields.set(idx, { name: c[col.field_path], v: c[col.value_b64u], len: Number(c[col.encoded_len]) });
  const view = c[col.projection];
  if (!s.views.has(view)) s.views.set(view, []);
  if (c[col.selected] === "1") s.views.get(view).push(idx);
}
const capsList = [...caps.entries()].slice(0, CAPSULES);

// ---------------- SD-JWT setup ----------------
const { privateKey, publicKey } = Crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const sd = new SDJwtInstance({
  signer: async (data) => Crypto.sign("sha256", Buffer.from(data), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url"),
  verifier: async (data, sig) => Crypto.verify("sha256", Buffer.from(data), { key: publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(sig, "base64url")),
  signAlg: "ES256",
  hasher: async (data, alg) => new Uint8Array(Crypto.createHash(alg.replace("-", "")).update(data).digest()),
  hashAlg: "sha-256",
  saltGenerator: async () => Crypto.randomBytes(16).toString("base64url"),
});

// ---------------- BBS setup ----------------
const CS = bbs.CIPHERSUITES.BLS12381_SHA256;
const bbsKeys = await bbs.generateKeyPair({ ciphersuite: CS });
const header = new Uint8Array();
const ph = new Uint8Array();

const stats = new Map();
const st = (view, variant) => {
  const k = `${view}|${variant}`;
  if (!stats.has(k)) stats.set(k, { view, variant, fields: 0, bytes: [], verifyUs: [], incTested: 0, incAccepted: 0, ok: true });
  return stats.get(k);
};

let warmed = false;
let ci = 0;
for (const [sid, s] of capsList) {
  const idxs = [...s.fields.keys()].sort((a, b) => a - b);
  const names = idxs.map((i) => s.fields.get(i).name);
  const claims = Object.fromEntries(idxs.map((i) => [s.fields.get(i).name, s.fields.get(i).v]));
  const credential = await sd.issue(claims, { _sd: names });
  const messages = idxs.map((i) => b64uToBytes(s.fields.get(i).v));
  const signature = await bbs.sign({ secretKey: bbsKeys.secretKey, publicKey: bbsKeys.publicKey, header, messages, ciphersuite: CS });

  for (const [view, sel] of s.views) {
    const selNames = sel.map((i) => s.fields.get(i).name);
    const frame = Object.fromEntries(selNames.map((n) => [n, true]));

    // ---- SD-JWT ----
    const pres = await sd.present(credential, frame);
    if (!warmed) { for (let w = 0; w < WARMUP; w++) await sd.verify(pres); }
    const a = st(view, "SD-JWT"); a.fields = sel.length; a.bytes.push(Buffer.byteLength(pres));
    for (let r = 0; r < REP_SD; r++) {
      const t0 = performance.now();
      try { await sd.verify(pres, { requiredClaimKeys: selNames }); } catch (e) { a.ok = false; }
      a.verifyUs.push((performance.now() - t0) * 1000);
    }

    // ---- BBS ----
    const pos = sel.map((i) => idxs.indexOf(i)).sort((x, y) => x - y);
    const proof = await bbs.deriveProof({ publicKey: bbsKeys.publicKey, signature, header, messages,
      presentationHeader: ph, disclosedMessageIndexes: pos, ciphersuite: CS });
    const disclosed = pos.map((p) => messages[p]);
    if (!warmed) { for (let w = 0; w < 3; w++) await bbs.verifyProof({ publicKey: bbsKeys.publicKey, proof, header, presentationHeader: ph, disclosedMessages: disclosed, disclosedMessageIndexes: pos, ciphersuite: CS }); warmed = true; }
    const b = st(view, "BBS"); b.fields = sel.length;
    b.bytes.push(proof.length + disclosed.reduce((acc, m) => acc + m.length, 0) + pos.length);
    for (let r = 0; r < REP_BBS; r++) {
      const t0 = performance.now();
      const ok = await bbs.verifyProof({ publicKey: bbsKeys.publicKey, proof, header, presentationHeader: ph,
        disclosedMessages: disclosed, disclosedMessageIndexes: pos, ciphersuite: CS });
      b.verifyUs.push((performance.now() - t0) * 1000);
      b.ok = b.ok && ok;
    }

    // ---- completeness: omit exactly one required field ----
    if (ci < INC_CAPS && sel.length > 1) {
      const aDef = st(view, "SD-JWT"); const aReq = st(view, "SD-JWT+requiredClaimKeys"); aReq.fields = sel.length;
      for (const omit of selNames) {
        const sub = Object.fromEntries(selNames.filter((n) => n !== omit).map((n) => [n, true]));
        const p = await sd.present(credential, sub);
        aDef.incTested++; aReq.incTested++;
        try { await sd.verify(p); aDef.incAccepted++; } catch (e) { /* rejected */ }
        try { await sd.verify(p, { requiredClaimKeys: selNames }); aReq.incAccepted++; } catch (e) { /* rejected */ }
      }
      for (const omitPos of pos) {
        const subPos = pos.filter((p) => p !== omitPos);
        const pr = await bbs.deriveProof({ publicKey: bbsKeys.publicKey, signature, header, messages,
          presentationHeader: ph, disclosedMessageIndexes: subPos, ciphersuite: CS });
        b.incTested++;
        const ok = await bbs.verifyProof({ publicKey: bbsKeys.publicKey, proof: pr, header, presentationHeader: ph,
          disclosedMessages: subPos.map((p) => messages[p]), disclosedMessageIndexes: subPos, ciphersuite: CS });
        b.incAccepted += ok ? 1 : 0;
      }
    }
  }
  ci++;
  if (ci % 10 === 0) console.log(`[progress] ${ci}/${capsList.length} capsules`);
}

// ES256 signature-verify cost alone (to separate it from disclosure checks)
const jws = Buffer.from("x".repeat(1200));
const sig = Crypto.sign("sha256", jws, { key: privateKey, dsaEncoding: "ieee-p1363" });
const sigUs = [];
for (let r = 0; r < 2000; r++) { const t0 = performance.now(); Crypto.verify("sha256", jws, { key: publicKey, dsaEncoding: "ieee-p1363" }, sig); sigUs.push((performance.now() - t0) * 1000); }

const out = ["view,variant,n_samples,disclosed_fields,total_bytes_median,verify_us_median,verify_us_p95,incomplete_tested,incomplete_accepted,all_verified,node_version"];
for (const v of stats.values()) {
  out.push([v.view, v.variant, v.verifyUs.length, v.fields, v.bytes.length ? median(v.bytes) : "",
    v.verifyUs.length ? median(v.verifyUs).toFixed(3) : "", v.verifyUs.length ? p95(v.verifyUs).toFixed(3) : "",
    v.incTested, v.incAccepted, v.ok, process.version].join(","));
}
out.push(["(es256-verify-only)", "ES256", sigUs.length, "", "", median(sigUs).toFixed(3), p95(sigUs).toFixed(3), "", "", true, process.version].join(","));
await fs.mkdir(OUT_DIR, { recursive: true });
const outPath = path.join(OUT_DIR, "sdjwt_bbs_e9_summary.csv");
await fs.writeFile(outPath, out.join("\n") + "\n");
console.log(out.join("\n"));
console.log("[OK]", outPath);
