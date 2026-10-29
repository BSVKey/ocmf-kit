// Carry one OCMF record in OCPP messages, and get it back out.
// 1.6 has no field for the method or key (they travel in vendor configuration keys such as
// MeterPublicKey[ConnectorId]); 2.0.1 and 2.1 have SignedMeterValueType.
import { split, signatureParams } from "./ocmf.mjs";
import { b64ToBytes, bytesToB64, utf8 } from "./keys.mjs";

// OCPP 1.6 SampledValue carrying the OCMF document.
export const toOcpp16SampledValue = (ocmf, o = {}) => ({
  value: ocmf,
  context: o.context ?? "Sample.Periodic",
  format: "SignedData",
  measurand: o.measurand ?? "Energy.Active.Import.Register",
  ...(o.location ? { location: o.location } : {}),
  unit: o.unit ?? "kWh",
});

// OCPP 2.0.1 / 2.1 SignedMeterValueType. In 2.0.1 all four fields are required; in 2.1
// signingMethod and publicKey are optional, so they can be left out with o.omitOptional.
export function toOcpp2SignedMeterValue(ocmf, publicKeyDer, o = {}) {
  const s = split(ocmf);
  if (!s.ok) throw new Error(`not OCMF: ${s.reason}`);
  const omit = o.version === "2.1" && o.omitOptional;
  return {
    signedMeterData: bytesToB64(utf8(ocmf)),
    encodingMethod: "OCMF",
    ...(omit ? {} : { signingMethod: signatureParams(s.signature).SA, publicKey: bytesToB64(publicKeyDer) }),
  };
}

// Pull the OCMF text out of a 1.6 SampledValue, a 2.x SignedMeterValueType, or plain text.
export function fromOcpp(x) {
  if (typeof x === "string") return x.trim();
  if (x && typeof x.signedMeterData === "string") {
    const raw = x.signedMeterData.trim();
    if (raw.startsWith("OCMF|")) return raw; // some stations send it unencoded
    const bytes = b64ToBytes(raw);
    return bytes ? new TextDecoder().decode(bytes) : raw;
  }
  if (x && x.format === "SignedData" && typeof x.value === "string") return x.value.trim();
  return null;
}

// The advertised key from a 2.x SignedMeterValueType (base64 DER), as hex for the checker.
export function publicKeyFromOcpp2(x) {
  const b = x && typeof x.publicKey === "string" ? b64ToBytes(x.publicKey) : null;
  return b ? Array.from(b, (v) => v.toString(16).padStart(2, "0")).join("") : null;
}
