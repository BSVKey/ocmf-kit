import { test } from "node:test";
import assert from "node:assert/strict";
import { createMeter, chargingSession, MODES } from "../src/generate.mjs";
import { checkSession, verifyRecord, EXPLAIN } from "../src/verify.mjs";
import { nodeCrypto, generateKey } from "../src/crypto-node.mjs";
import { ALGORITHMS, bytesToHex, derToRaw, hexToBytes } from "../src/keys.mjs";
import { toOcpp16SampledValue, toOcpp2SignedMeterValue, fromOcpp, publicKeyFromOcpp2 } from "../src/ocpp.mjs";
import { parse, stringify } from "../src/json-raw.mjs";
import { sub, cmp } from "../src/decimal.mjs";

// Which problem code each failing mode must produce.
const EXPECT = {
  valid: null,
  tampered_payload: "signature_invalid",
  wrong_key: "signature_invalid",
  invalid_signature: "signature_invalid",
  replayed_page: "page_repeated",
  missing_page: "page_missing",
  meter_swapped: "meter_changed",
  register_backwards: "register_went_backwards",
  energy_error_flag: "energy_error_flag",
  meter_fault: "meter_status",
  whitespace_changed: "signature_invalid",
  number_reformatted: "signature_invalid",
  unsynchronized_clock: null,
  hostile_text: null,
};

test("every mode has an expected outcome and plain-words text", () => {
  assert.deepEqual(Object.keys(EXPECT).sort(), Object.keys(MODES).sort());
  for (const code of Object.values(EXPECT)) if (code) assert.ok(EXPLAIN[code], code);
});

for (const format of ["SR", "MR"]) {
  for (const mode of Object.keys(MODES)) {
    if (format === "MR" && ["replayed_page", "missing_page", "meter_swapped"].includes(mode)) continue;
    test(`${format} ${mode}`, async () => {
      const meter = createMeter();
      const s = chargingSession(meter, { mode, format });
      const r = await checkSession(s.records, s.publicKey, nodeCrypto);
      const want = EXPECT[mode];
      if (want === null) {
        assert.equal(r.ok, true, JSON.stringify(r.problems));
        if (mode !== "register_backwards") assert.equal(r.energy.delivered, "7.825");
      } else {
        assert.equal(r.ok, false);
        assert.ok(r.problems.some((p) => p.code === want), `${mode}: got ${JSON.stringify(r.problems)}`);
      }
      if (mode === "unsynchronized_clock") assert.ok(r.warnings.some((w) => w.code === "clock_unsynchronized"));
    });
  }
}

test("records out of order still form one session", async () => {
  const meter = createMeter();
  const s = chargingSession(meter);
  const r = await checkSession([...s.records].reverse(), s.publicKey, nodeCrypto);
  assert.equal(r.ok, true);
});

test("two sessions in a row keep counting pages and the register", async () => {
  const meter = createMeter();
  const a = chargingSession(meter), b = chargingSession(meter);
  assert.equal((await checkSession(b.records, b.publicKey, nodeCrypto)).energy.begin, (await checkSession(a.records, a.publicKey, nodeCrypto)).energy.end);
  // Mixing one record from each is caught.
  const mixed = await checkSession([a.records[0], b.records[1]], a.publicKey, nodeCrypto);
  assert.ok(mixed.problems.some((p) => p.code === "page_missing"));
});

test("billed energy is compared exactly", async () => {
  const meter = createMeter();
  const s = chargingSession(meter);
  assert.equal((await checkSession(s.records, s.publicKey, nodeCrypto, { billedEnergy: "7.825" })).ok, true);
  const r = await checkSession(s.records, s.publicKey, nodeCrypto, { billedEnergy: "7.83" });
  assert.ok(r.problems.some((p) => p.code === "billed_energy_mismatch"));
});

for (const SA of Object.keys(ALGORITHMS)) {
  test(`signs and verifies with ${SA}`, async () => {
    const meter = createMeter({ algorithm: SA });
    const s = chargingSession(meter);
    assert.equal((await checkSession(s.records, s.publicKey, nodeCrypto)).ok, true);
  });
}

test("a key on another curve is refused before any signature check", async () => {
  const meter = createMeter();
  const s = chargingSession(meter);
  const r = await verifyRecord(s.records[0], bytesToHex(generateKey("secp384r1").spki), nodeCrypto);
  assert.equal(r.reason, "key_algorithm_mismatch");
});

test("a key given as a bare point, base64 or PEM works", async () => {
  const meter = createMeter();
  const s = chargingSession(meter);
  const pem = `-----BEGIN PUBLIC KEY-----\n${meter.publicKeyB64}\n-----END PUBLIC KEY-----`;
  const point = meter.publicKeyHex.slice(-130);
  for (const k of [meter.publicKeyHex, meter.publicKeyB64, pem, point]) assert.equal((await verifyRecord(s.records[0], k, nodeCrypto)).ok, true, k.slice(0, 20));
});

test("malformed containers are named, not thrown", async () => {
  const k = createMeter().publicKeyHex;
  const cases = { "": "not_ocmf", "OCMF|{}": "wrong_section_count", "OCMF|{x}|{}": "payload_not_json", "OCMF|{}|{}|{}": "wrong_section_count", 'OCMF|{"a":1,"a":2}|{"SD":"00"}': "payload_not_json", "OCMF|{}|{}": "signature_data_missing", 'OCMF|{}|{"SD":"3006020101020101","SA":"RSA"}': "algorithm_unknown" };
  for (const [text, reason] of Object.entries(cases)) assert.equal((await verifyRecord(text, k, nodeCrypto)).reason, reason, text);
});

test("OCPP 1.6 and 2.x carriers round-trip the exact record", async () => {
  const meter = createMeter();
  const s = chargingSession(meter);
  const sv = toOcpp16SampledValue(s.records[0], { context: "Transaction.Begin" });
  assert.equal(sv.format, "SignedData");
  assert.equal(fromOcpp(sv), s.records[0]);
  const smv = toOcpp2SignedMeterValue(s.records[0], meter.key.spki);
  assert.deepEqual(Object.keys(smv).sort(), ["encodingMethod", "publicKey", "signedMeterData", "signingMethod"]);
  assert.equal(fromOcpp(smv), s.records[0]);
  assert.equal(publicKeyFromOcpp2(smv).toUpperCase(), meter.publicKeyHex);
  assert.equal((await verifyRecord(fromOcpp(smv), publicKeyFromOcpp2(smv), nodeCrypto)).ok, true);
  const lean = toOcpp2SignedMeterValue(s.records[0], meter.key.spki, { version: "2.1", omitOptional: true });
  assert.deepEqual(Object.keys(lean).sort(), ["encodingMethod", "signedMeterData"]);
});

test("numbers keep their written form", () => {
  const t = '{"RV":2935.600,"CL":0.5,"X":[1e3,-0]}';
  assert.equal(stringify(parse(t)), t);
  assert.equal(sub("1241.925", "1234.1"), "7.825");
  assert.equal(sub("0.000", "0.100"), "-0.100");
  assert.equal(cmp("2935.600", "2935.6"), 0);
});

test("DER to raw signature conversion is strict", () => {
  assert.equal(bytesToHex(derToRaw(hexToBytes("3006020101020102"), 32)), "00".repeat(31) + "01" + "00".repeat(31) + "02");
  assert.equal(derToRaw(hexToBytes("3007020101020102"), 32), null);
  assert.equal(derToRaw(hexToBytes("DEADBEEF"), 32), null);
});
