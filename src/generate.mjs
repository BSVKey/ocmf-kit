// A simulated signing meter that writes real, verifiable OCMF records, plus the ways a
// record can go wrong so a backend's rejection path can be tested.
// This simulates the wire format. It is not a calibrated meter and its output is not
// legally valid metering data.
import { generateKey, signDer } from "./crypto-node.mjs";
import { ALGORITHMS, bytesToHex, bytesToB64, utf8 } from "./keys.mjs";
import { Num } from "./json-raw.mjs";
import { serializePayload, assemble, formatTime } from "./ocmf.mjs";

// The four modes from ocpp-cp-simulator#315, then extra cases a session checker must catch.
export const MODES = {
  valid: "accept",
  tampered_payload: "reject: a reading was changed after signing",
  wrong_key: "reject: signed by a different key than the one advertised",
  invalid_signature: "reject: signature block is garbage",
  replayed_page: "reject: the same page number is sent twice",
  missing_page: "reject: a record in the middle is missing",
  meter_swapped: "reject: end record comes from another meter serial",
  register_backwards: "reject: the end reading is lower than the start",
  energy_error_flag: "reject: the meter flagged the energy value unusable",
  meter_fault: "reject: meter status is not G (good)",
  whitespace_changed: "reject: whitespace in the signed part was changed",
  number_reformatted: "reject: 1234.500 rewritten as 1234.5000 (same number, but the signed text changed)",
  unsynchronized_clock: "accept with warning: meter clock not synchronized",
  hostile_text: "accept: valid signature, but text fields carry HTML and script; a checker must show them as text",
};

export function createMeter(o = {}) {
  const SA = o.algorithm ?? "ECDSA-secp256r1-SHA256";
  const algo = ALGORITHMS[SA];
  if (!algo) throw new Error(`unknown algorithm ${SA}`);
  const key = o.key ?? generateKey(algo.curve);
  const meter = {
    SA, key,
    publicKeyHex: bytesToHex(key.spki),
    publicKeyB64: bytesToB64(key.spki),
    vendor: o.vendor ?? "BSVKey Simulator",
    model: o.model ?? "SIM-OCMF-1",
    serial: o.serial ?? "SIM-0001",
    firmware: o.firmware ?? "1.0",
    gateway: o.gateway ?? "ocmf-kit",
    gatewaySerial: o.gatewaySerial ?? "GW-0001",
    gatewayVersion: o.gatewayVersion ?? "0.1.0",
    page: o.page ?? 1,
    registerWh: BigInt(o.registerWh ?? 1234500),
  };
  meter.sign = (payloadObj) => {
    const payloadRaw = serializePayload(payloadObj);
    const sd = signDer(meter.key.privateKey, utf8(payloadRaw), algo.hash);
    return assemble(payloadRaw, { SA, SE: "hex", SM: "application/x-der", SD: bytesToHex(sd) });
  };
  return meter;
}

const kwh = (wh) => new Num(`${wh / 1000n}.${String(wh % 1000n).padStart(3, "0")}`);

// One charging session as OCMF records.
//   format "SR": begin and end in two records (SingleReading); "MR": one record with both.
// Returns { records, publicKey (hex), mode, expect }.
export function chargingSession(meter, o = {}) {
  const mode = o.mode ?? "valid";
  if (!(mode in MODES)) throw new Error(`unknown mode ${mode}`);
  const format = o.format ?? "SR";
  const start = o.start ?? Date.UTC(2026, 9, 29, 8, 0, 0);
  const minutes = o.minutes ?? 75;
  const energyWh = BigInt(o.energyWh ?? 7825);
  const sync = mode === "unsynchronized_clock" ? "U" : "S";
  const hostile = mode === "hostile_text";

  const begin = meter.registerWh;
  let end = begin + energyWh;
  if (mode === "register_backwards") end = begin - 1000n;
  meter.registerWh = end;

  const reading = (tx, wh, at) => ({
    TM: formatTime(at, sync), TX: tx, RV: kwh(wh), RI: "01-00:01.08.00*FF", RU: "kWh", RT: o.currentType ?? "AC",
    EF: mode === "energy_error_flag" && tx !== "B" ? "E" : "",
    ST: mode === "meter_fault" && tx !== "B" ? "M" : "G",
  });
  const head = (page, serial = meter.serial) => ({
    FV: "1.4", GI: meter.gateway, GS: meter.gatewaySerial, GV: meter.gatewayVersion, PG: `T${page}`,
    MV: meter.vendor, MM: meter.model, MS: serial, MF: meter.firmware,
    IS: true, IL: "TRUSTED", IF: ["OCPP_AUTH"], IT: "ISO14443", ID: o.idTag ?? "04A2B3C4D5E6F7",
    ...(hostile ? { TT: '<img src=x onerror=alert(1)>"Tariff"</script><script>alert(2)</script>' } : {}),
    ...(o.chargePoint ? { CT: "CBIDC", CI: o.chargePoint } : {}),
  });
  const B = reading("B", begin, start);
  const E = reading("E", end, start + minutes * 60000);

  let records;
  if (format === "MR") {
    records = [meter.sign({ ...head(meter.page++), RD: [B, E] })];
  } else {
    const p1 = meter.page++;
    if (mode === "missing_page") meter.page++;
    const p2 = mode === "replayed_page" ? p1 : meter.page++;
    records = [
      meter.sign({ ...head(p1), RD: [B] }),
      meter.sign({ ...head(p2, mode === "meter_swapped" ? `${meter.serial}-X` : meter.serial), RD: [E] }),
    ];
  }
  const last = records.length - 1;
  let publicKey = meter.publicKeyHex;
  if (mode === "tampered_payload") records[last] = records[last].replace(/"RV":(\d+\.\d+)/, (m, v) => `"RV":${bumpLastDigit(v)}`);
  if (mode === "wrong_key") publicKey = bytesToHex(generateKey(meter.key.curve).spki);
  if (mode === "invalid_signature") records[last] = records[last].replace(/"SD":"[0-9A-F]+"/, `"SD":"${"DEADBEEF".repeat(9)}"`);
  if (mode === "whitespace_changed") records[last] = records[last].replace('{"FV"', '{ "FV"');
  // Same number, different text (as a JSON parse and re-serialize can do).
  if (mode === "number_reformatted") records[0] = records[0].replace(/"RV":(\d+\.\d+)/, '"RV":$10');
  if (mode === "missing_page" && format === "MR") throw new Error("missing_page needs format SR");
  return { records, publicKey, mode, expect: MODES[mode] };
}

const bumpLastDigit = (v) => v.slice(0, -1) + String((Number(v.at(-1)) + 1) % 10);
