// Writes fixtures/: one folder per mode with the records, the advertised public key and
// the expected verdict, so any OCMF checker (in any language) can be tested against them.
// Keys are fresh each run; commit the output to pin a set.
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { createMeter, chargingSession, MODES } from "../src/generate.mjs";
import { checkSession } from "../src/verify.mjs";
import { nodeCrypto } from "../src/crypto-node.mjs";

const out = new URL("../fixtures/", import.meta.url);
rmSync(out, { recursive: true, force: true });
const manifest = [];
for (const format of ["SR", "MR"]) {
  for (const mode of Object.keys(MODES)) {
    if (format === "MR" && ["replayed_page", "missing_page", "meter_swapped"].includes(mode)) continue;
    const meter = createMeter({ serial: `SIM-${format}-${mode}`.slice(0, 40) });
    const s = chargingSession(meter, { mode, format });
    const r = await checkSession(s.records, s.publicKey, nodeCrypto);
    const dir = new URL(`${format}-${mode}/`, out);
    mkdirSync(dir, { recursive: true });
    writeFileSync(new URL("records.ocmf", dir), s.records.join("\n") + "\n");
    writeFileSync(new URL("publicKey.hex", dir), s.publicKey + "\n");
    const expected = { mode, format, expect: s.expect, valid: r.ok, problems: r.problems.map((p) => p.code), warnings: r.warnings.map((w) => w.code), energy: r.energy?.delivered ?? null };
    writeFileSync(new URL("expected.json", dir), JSON.stringify(expected, null, 2) + "\n");
    manifest.push({ dir: `${format}-${mode}`, ...expected });
  }
}
writeFileSync(new URL("manifest.json", out), JSON.stringify(manifest, null, 2) + "\n");
console.log(`${manifest.length} fixture sets in fixtures/`);
