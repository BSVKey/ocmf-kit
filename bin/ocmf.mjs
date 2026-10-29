#!/usr/bin/env node
// ocmf check <file>... --key <hex|base64|pem file> [--billed 7.825] [--json]
// ocmf gen [--mode valid] [--format SR|MR] [--algorithm ECDSA-secp256r1-SHA256] [--ocpp 1.6|2.0.1|2.1]
// ocmf modes
// Files may hold one OCMF record per line, a JSON array of records, or OCPP carriers.
import { readFileSync, existsSync } from "node:fs";
import { checkSession, EXPLAIN, nodeCrypto, createMeter, chargingSession, MODES, toOcpp16SampledValue, toOcpp2SignedMeterValue, fromOcpp, publicKeyFromOcpp2 } from "../src/index.mjs";

const [cmd, ...rest] = process.argv.slice(2);
const flags = {}, files = [];
for (let i = 0; i < rest.length; i++) {
  if (rest[i].startsWith("--")) { const k = rest[i].slice(2); flags[k] = rest[i + 1] && !rest[i + 1].startsWith("--") ? rest[++i] : true; }
  else files.push(rest[i]);
}

function recordsFrom(text) {
  const t = text.trim();
  if (t.startsWith("[") || t.startsWith("{")) {
    const v = JSON.parse(t);
    return (Array.isArray(v) ? v : [v]).map((x) => ({ ocmf: fromOcpp(x), key: publicKeyFromOcpp2(x) })).filter((x) => x.ocmf);
  }
  // One record per OCMF| start, so pretty-printed multi-line records work too.
  return t.split(/(?=^OCMF\|)/m).map((s) => ({ ocmf: s.trim(), key: null })).filter((x) => x.ocmf);
}

if (cmd === "check") {
  if (!files.length) { console.error("usage: ocmf check <file>... --key <key or key file>"); process.exit(2); }
  const recs = files.flatMap((f) => recordsFrom(readFileSync(f, "utf8")));
  let key = typeof flags.key === "string" ? (existsSync(flags.key) ? readFileSync(flags.key, "utf8") : flags.key) : recs.find((r) => r.key)?.key;
  if (!key) { console.error("no public key: pass --key (the key must come from the meter label or a key register, not from the data being checked)"); process.exit(2); }
  const r = await checkSession(recs.map((x) => x.ocmf), key, nodeCrypto, flags.billed ? { billedEnergy: flags.billed } : {});
  if (flags.json) console.log(JSON.stringify(r, null, 2));
  else {
    console.log(r.ok ? "VALID" : "INVALID", `(${recs.length} record${recs.length === 1 ? "" : "s"}, meter ${r.meter?.serial ?? "?"})`);
    for (const x of r.records) console.log(`  record ${x.index + 1} ${x.page ?? ""}: ${x.ok ? "signature good" : EXPLAIN[x.reason] ?? x.reason}`);
    if (r.energy) console.log(`${r.ok ? "energy" : "claimed energy (NOT proven)"} ${r.energy.delivered} ${r.energy.unit} (${r.energy.begin} -> ${r.energy.end}, register ${r.energy.register})`);
    for (const p of r.problems) console.log(`  problem: ${EXPLAIN[p.code] ?? p.code}${p.record !== null ? ` [record ${p.record + 1}]` : ""}${p.detail ? ` (${p.detail})` : ""}`);
    for (const w of r.warnings) console.log(`  warning: ${EXPLAIN[w.code] ?? w.code}${w.record !== null ? ` [record ${w.record + 1}]` : ""}`);
  }
  process.exit(r.ok ? 0 : 1);
} else if (cmd === "gen") {
  const meter = createMeter({ algorithm: flags.algorithm });
  const s = chargingSession(meter, { mode: flags.mode ?? "valid", format: flags.format ?? "SR" });
  if (flags.ocpp === "1.6") console.log(JSON.stringify(s.records.map((r, i) => toOcpp16SampledValue(r, { context: i === 0 ? "Transaction.Begin" : "Transaction.End" })), null, 2));
  else if (flags.ocpp) console.log(JSON.stringify(s.records.map((r) => toOcpp2SignedMeterValue(r, meter.key.spki, { version: flags.ocpp })), null, 2));
  else console.log(s.records.join("\n"));
  console.error(`mode ${s.mode}: ${s.expect}\npublic key (hex DER): ${s.publicKey}`);
} else if (cmd === "modes") {
  for (const [m, d] of Object.entries(MODES)) console.log(`${m.padEnd(22)} ${d}`);
} else {
  console.log("ocmf check <file>... --key <key> [--billed kWh] [--json]\nocmf gen [--mode m] [--format SR|MR] [--algorithm SA] [--ocpp 1.6|2.0.1|2.1]\nocmf modes");
  process.exit(cmd ? 2 : 0);
}
