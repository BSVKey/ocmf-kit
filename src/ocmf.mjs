// The OCMF container: OCMF|<payload>|<signature>.
// The payload section is signed byte for byte, so it is kept as the exact text received.
import { parse, stringify, numText } from "./json-raw.mjs";

export const DEFAULT_SA = "ECDSA-secp256r1-SHA256";
const END_TX = new Set(["E", "L", "R", "A", "P"]);
export const isEndTx = (tx) => END_TX.has(tx);

// { ok:true, payloadRaw, payload, signatureRaw, signature } / { ok:false, reason }
export function split(text) {
  if (typeof text !== "string") return { ok: false, reason: "not_a_string" };
  const parts = text.replace(/^﻿/, "").trim().split("|");
  if (parts[0] !== "OCMF") return { ok: false, reason: "not_ocmf" };
  // Pipes are not allowed inside sections, so anything but three parts is malformed.
  if (parts.length !== 3) return { ok: false, reason: "wrong_section_count" };
  const [, payloadRaw, signatureRaw] = parts;
  let payload, signature;
  try { payload = parse(payloadRaw); } catch (e) { return { ok: false, reason: "payload_not_json", detail: e.message }; }
  try { signature = parse(signatureRaw); } catch (e) { return { ok: false, reason: "signature_not_json", detail: e.message }; }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return { ok: false, reason: "payload_not_object" };
  if (!signature || typeof signature !== "object" || Array.isArray(signature)) return { ok: false, reason: "signature_not_object" };
  if (typeof signature.SD !== "string" || !signature.SD) return { ok: false, reason: "signature_data_missing" };
  return { ok: true, payloadRaw, payload, signatureRaw, signature };
}

export const signatureParams = (sig) => ({
  SA: sig.SA ?? DEFAULT_SA,
  SE: sig.SE ?? "hex",
  SM: sig.SM ?? "application/x-der",
  SD: sig.SD,
});

// Readings with omitted fields filled from the previous reading in the same record,
// as the spec allows ("fields identical to the previous reading are omitted").
export function readings(payload) {
  const out = [];
  let prev = {};
  for (const r of Array.isArray(payload.RD) ? payload.RD : []) {
    const full = { ...prev, ...r };
    out.push(full);
    prev = full;
  }
  return out;
}

// "2018-07-24T13:22:04,000+0200 S" -> { at: ms or null, sync: "S" }
export function parseTime(tm) {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}),(\d{3})([+-]\d{2})(\d{2})(?: ([UISR]))?$/.exec(String(tm ?? ""));
  if (!m) return { at: null, sync: null };
  const at = Date.parse(`${m[1]}.${m[2]}${m[3]}:${m[4]}`);
  return { at: Number.isNaN(at) ? null : at, sync: m[5] ?? null };
}

export function formatTime(ms, sync = "S", offsetMin = 0) {
  const d = new Date(ms + offsetMin * 60000);
  const p = (n, w = 2) => String(n).padStart(w, "0");
  const sign = offsetMin < 0 ? "-" : "+";
  const o = Math.abs(offsetMin);
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())},${p(d.getUTCMilliseconds(), 3)}${sign}${p(Math.floor(o / 60))}${p(o % 60)} ${sync}`;
}

// "T12345" -> { context:"T", n:12345 }
export function parsePage(pg) {
  const m = /^([TF])(0|[1-9]\d*)$/.exec(String(pg ?? ""));
  return m ? { context: m[1], n: Number(m[2]) } : null;
}

export const assemble = (payloadRaw, signature) => `OCMF|${payloadRaw}|${stringify(signature)}`;
export const serializePayload = stringify;
export { numText };
