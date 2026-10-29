// Check one OCMF record, or a whole charging session made of one or more records.
// Session rules follow OCMF "Signing and Verification Process": first record marks the
// start, last the end, no record removed or added in between (pagination), error states
// fail the check, and every record comes from the same meter.
import { split, signatureParams, readings, parseTime, parsePage, isEndTx, numText } from "./ocmf.mjs";
import { ALGORITHMS, decodePublicKey, decodeSignature, buildSpki, utf8 } from "./keys.mjs";
import { cmp, sub, isDecimal } from "./decimal.mjs";

// { ok, reason?, algorithm?, meter?, page?, readings?, payload? }
export async function verifyRecord(text, publicKey, adapter) {
  const s = split(text);
  if (!s.ok) return s;
  const { SA, SE, SM, SD } = signatureParams(s.signature);
  const algo = ALGORITHMS[SA];
  const base = { algorithm: SA, meter: meterOf(s.payload), page: s.payload.PG ?? null, readings: readings(s.payload), payload: s.payload };
  if (!algo) return { ...base, ok: false, reason: "algorithm_unknown" };
  if (SM !== "application/x-der") return { ...base, ok: false, reason: "signature_format_unknown" };
  if (SE !== "hex" && SE !== "base64") return { ...base, ok: false, reason: "signature_encoding_unknown" };
  const sigDer = decodeSignature(SD, SE);
  if (!sigDer || !sigDer.length) return { ...base, ok: false, reason: "signature_unreadable" };
  const key = decodePublicKey(publicKey);
  if (key.error) return { ...base, ok: false, reason: key.error };
  let spki = key.spki;
  if (key.point) {
    if (!key.candidates.includes(algo.curve)) return { ...base, ok: false, reason: "key_algorithm_mismatch" };
    spki = buildSpki(algo.curve, key.point);
  } else if (key.curve !== algo.curve) return { ...base, ok: false, reason: "key_algorithm_mismatch" };
  if (!adapter.supports(algo.curve)) return { ...base, ok: false, reason: "curve_not_supported_here" };
  let good = false;
  try { good = await adapter.verify({ curve: algo.curve, hash: algo.hash, spki, data: utf8(s.payloadRaw), sigDer }); } catch { good = false; }
  return good ? { ...base, ok: true } : { ...base, ok: false, reason: "signature_invalid" };
}

const meterOf = (p) => ({ vendor: p.MV ?? null, model: p.MM ?? null, serial: p.MS ?? null, gateway: p.GI ?? null, gatewaySerial: p.GS ?? null });

// texts: OCMF strings in any order. Returns a verdict a person can act on.
export async function checkSession(texts, publicKey, adapter, opts = {}) {
  const problems = [], warnings = [];
  const add = (list, code, record, detail) => list.push({ code, record, ...(detail ? { detail } : {}) });
  const records = [];
  for (let i = 0; i < texts.length; i++) {
    const r = await verifyRecord(texts[i], publicKey, adapter);
    records.push({ index: i, ...r });
    if (!r.ok) add(problems, r.reason, i);
  }
  const parsed = records.filter((r) => r.payload);
  if (!parsed.length) return finish();

  // Same meter throughout.
  const first = parsed[0].meter;
  for (const r of parsed.slice(1)) {
    if (r.meter.serial !== first.serial) add(problems, "meter_changed", r.index, `${first.serial} -> ${r.meter.serial}`);
    else if (r.meter.gatewaySerial !== first.gatewaySerial) add(problems, "gateway_changed", r.index, `${first.gatewaySerial} -> ${r.meter.gatewaySerial}`);
  }
  if (!first.serial) add(problems, "meter_serial_missing", parsed[0].index);

  // Pagination: transaction context, no repeats, no gaps.
  const pages = parsed.map((r) => ({ r, pg: parsePage(r.page) }));
  for (const { r, pg } of pages) {
    if (!pg) add(problems, "page_unreadable", r.index, String(r.page));
    else if (pg.context !== "T") add(problems, "not_a_transaction_record", r.index, r.page);
  }
  const ordered = pages.filter((x) => x.pg).sort((a, b) => a.pg.n - b.pg.n);
  for (let k = 1; k < ordered.length; k++) {
    const gap = ordered[k].pg.n - ordered[k - 1].pg.n;
    if (gap === 0) add(problems, "page_repeated", ordered[k].r.index, ordered[k].r.page);
    else if (gap > 1) add(problems, "page_missing", ordered[k].r.index, `T${ordered[k - 1].pg.n + 1}${gap > 2 ? `..T${ordered[k].pg.n - 1}` : ""}`);
  }

  // Readings across the session in page order.
  const all = [];
  for (const { r } of ordered) for (const rd of r.readings) all.push({ rd, record: r.index });
  const valued = all.filter((x) => x.rd.RV !== undefined);
  if (!valued.length) { add(problems, "no_readings", parsed[0].index); return finish(); }
  if (valued[0].rd.TX !== "B") add(problems, "no_begin", valued[0].record);
  if (!isEndTx(valued[valued.length - 1].rd.TX)) add(problems, "no_end", valued[valued.length - 1].record);
  const register = valued[0].rd.RI ?? null;

  const lastByRegister = new Map(), unitByRegister = new Map();
  let lastAt = null, beginsSeen = 0;
  for (const { rd, record } of all) {
    if (rd.TX === "B" && rd.RI === register) beginsSeen++;
    if (rd.TX === "X") add(problems, "exception_during_charging", record);
    if (rd.ST !== undefined && rd.ST !== "G") add(problems, "meter_status", record, String(rd.ST));
    const ef = String(rd.EF ?? "");
    if (ef.includes("E")) add(problems, "energy_error_flag", record);
    if (ef.includes("t")) add(warnings, "time_error_flag", record);
    const { at, sync } = parseTime(rd.TM);
    if (at === null) add(problems, "time_unreadable", record, String(rd.TM));
    else {
      if (lastAt !== null && at < lastAt) add(problems, "time_went_backwards", record, String(rd.TM));
      lastAt = at;
    }
    if (sync === "U") add(warnings, "clock_unsynchronized", record);
    else if (sync === "I") add(warnings, "clock_informative", record);
    if (rd.RV === undefined) continue;
    const v = numText(rd.RV);
    if (!isDecimal(v)) { add(problems, "reading_not_a_number", record, String(v)); continue; }
    const key = rd.RI ?? "";
    if (unitByRegister.has(key) && unitByRegister.get(key) !== rd.RU) add(problems, "unit_changed", record, `${unitByRegister.get(key)} -> ${rd.RU}`);
    unitByRegister.set(key, rd.RU);
    // A new B starts a fresh count for registers that reset per transaction (B3 etc.).
    if (lastByRegister.has(key) && rd.TX !== "B" && cmp(v, lastByRegister.get(key)) < 0) add(problems, "register_went_backwards", record, `${key}: ${lastByRegister.get(key)} -> ${v}`);
    lastByRegister.set(key, v);
  }
  if (beginsSeen > 1) add(problems, "second_begin", null);

  const reg = valued.filter((x) => x.rd.RI === register);
  const b = reg.find((x) => x.rd.TX === "B");
  const e = [...reg].reverse().find((x) => isEndTx(x.rd.TX));
  const energy = b && e ? {
    register, unit: b.rd.RU ?? null,
    begin: numText(b.rd.RV), end: numText(e.rd.RV),
    delivered: sub(numText(e.rd.RV), numText(b.rd.RV)),
    cableLoss: e.rd.CL !== undefined ? numText(e.rd.CL) : null,
    beginTime: b.rd.TM, endTime: e.rd.TM,
  } : null;
  if (energy && opts.billedEnergy !== undefined && cmp(String(opts.billedEnergy), energy.delivered) !== 0)
    add(problems, "billed_energy_mismatch", null, `billed ${opts.billedEnergy}, signed ${energy.delivered}`);
  return finish(energy);

  function finish(energy = null) {
    return {
      ok: problems.length === 0,
      verdict: problems.length === 0 ? "valid" : "invalid",
      problems, warnings, energy,
      meter: parsed[0]?.meter ?? null,
      identification: parsed[0] ? { status: parsed[0].payload.IS ?? null, level: parsed[0].payload.IL ?? null, type: parsed[0].payload.IT ?? null, id: parsed[0].payload.ID ?? null } : null,
      records: records.map(({ payload, readings: rds, ...r }) => r),
    };
  }
}

// Plain-words text for each problem code, for people reading a verdict.
export const EXPLAIN = {
  not_ocmf: "This is not an OCMF record (it should start with OCMF|).",
  wrong_section_count: "The record does not have exactly three parts separated by |.",
  payload_not_json: "The data part is not valid JSON.",
  signature_not_json: "The signature part is not valid JSON.",
  signature_data_missing: "There is no signature (SD).",
  algorithm_unknown: "The signature method is not one OCMF defines.",
  signature_format_unknown: "The signature format is not DER.",
  signature_encoding_unknown: "The signature encoding is not hex or base64.",
  signature_unreadable: "The signature cannot be decoded.",
  public_key_missing: "No public key was given.",
  public_key_unreadable: "The public key cannot be read.",
  public_key_curve_unknown: "The public key is not on a curve OCMF uses.",
  key_algorithm_mismatch: "The public key is for a different curve than the signature says.",
  curve_not_supported_here: "This browser cannot check this curve. Use the command-line checker.",
  signature_invalid: "The signature does not match this data and key. The data was changed, or it was not signed by this meter.",
  meter_changed: "Records come from different meters.",
  gateway_changed: "Records come from different gateways.",
  meter_serial_missing: "The meter serial number (MS) is missing.",
  page_unreadable: "The page number (PG) cannot be read.",
  not_a_transaction_record: "A record is a fiscal reading, not part of a charging session.",
  page_repeated: "The same page number appears twice (a record was repeated or replayed).",
  page_missing: "A page number is skipped (a record is missing).",
  no_readings: "There are no meter readings.",
  no_begin: "The first reading is not marked as the start of charging.",
  no_end: "The last reading is not marked as the end of charging.",
  second_begin: "More than one start-of-charging reading.",
  exception_during_charging: "The meter reported an error during charging; values after it cannot be used.",
  meter_status: "The meter was not in good state when it took a reading.",
  energy_error_flag: "The meter flagged the energy value as unusable.",
  time_unreadable: "A reading time cannot be read.",
  time_went_backwards: "Reading times go backwards.",
  reading_not_a_number: "A reading value is not a number.",
  unit_changed: "The unit changes within the session.",
  register_went_backwards: "The meter count goes down.",
  billed_energy_mismatch: "The billed energy is not what the meter signed.",
  time_error_flag: "The meter flagged the time as unusable for billing.",
  clock_unsynchronized: "The meter clock was not synchronized.",
  clock_informative: "The meter clock was informative only, not legally synchronized.",
};
