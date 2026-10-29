// Algorithm table, key text decoding and signature encodings, with no platform crypto.
// Table 22 of OCMF 1.4: every listed method hashes with SHA-256, the 384-bit curves included.
export const ALGORITHMS = {
  "ECDSA-secp192k1-SHA256": { curve: "secp192k1", size: 24, hash: "SHA-256" },
  "ECDSA-secp256k1-SHA256": { curve: "secp256k1", size: 32, hash: "SHA-256" },
  "ECDSA-secp192r1-SHA256": { curve: "secp192r1", size: 24, hash: "SHA-256" },
  "ECDSA-secp256r1-SHA256": { curve: "secp256r1", size: 32, hash: "SHA-256" },
  "ECDSA-brainpool256r1-SHA256": { curve: "brainpool256r1", size: 32, hash: "SHA-256" },
  "ECDSA-secp384r1-SHA256": { curve: "secp384r1", size: 48, hash: "SHA-256" },
  "ECDSA-brainpool384r1-SHA256": { curve: "brainpool384r1", size: 48, hash: "SHA-256" },
};

// Curve OIDs as they appear (DER-encoded) inside a SubjectPublicKeyInfo.
const CURVE_OIDS = {
  "2a8648ce3d030107": "secp256r1",
  "2b81040022": "secp384r1",
  "2b8104000a": "secp256k1",
  "2a8648ce3d030101": "secp192r1",
  "2b8104001f": "secp192k1",
  "2b2403030208010107": "brainpool256r1",
  "2b240303020801010b": "brainpool384r1",
};

// Uncompressed point length per curve, for keys published as a bare 04||X||Y.
const POINT_LEN = { 49: ["secp192r1", "secp192k1"], 65: ["secp256r1", "secp256k1", "brainpool256r1"], 97: ["secp384r1", "brainpool384r1"] };

export const hexToBytes = (h) => {
  const s = String(h).replace(/\s+/g, "");
  if (s.length % 2 || /[^0-9a-fA-F]/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
};
export const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
export const b64ToBytes = (s) => {
  const clean = String(s).replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) return null;
  const bin = atob(clean);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
export const bytesToB64 = (b) => btoa(String.fromCharCode(...b));
export const utf8 = (s) => new TextEncoder().encode(s);

// Accepts PEM, hex DER SPKI, base64 DER SPKI, or a bare uncompressed point in hex.
// Returns { spki } or { point, candidates } or { error }.
export function decodePublicKey(text) {
  const t = String(text ?? "").trim();
  if (!t) return { error: "public_key_missing" };
  let bytes;
  const pem = /-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/.exec(t);
  if (pem) bytes = b64ToBytes(pem[1]);
  else bytes = hexToBytes(t) ?? b64ToBytes(t);
  if (!bytes || !bytes.length) return { error: "public_key_unreadable" };
  if (bytes[0] === 0x30) {
    const curve = curveOfSpki(bytes);
    return curve ? { spki: bytes, curve } : { error: "public_key_curve_unknown" };
  }
  if (bytes[0] === 0x04 && POINT_LEN[bytes.length]) return { point: bytes, candidates: POINT_LEN[bytes.length] };
  return { error: "public_key_unreadable" };
}

export function curveOfSpki(der) {
  const hex = bytesToHex(der).toLowerCase();
  if (!hex.includes("2a8648ce3d0201")) return null; // id-ecPublicKey
  for (const [oid, name] of Object.entries(CURVE_OIDS)) if (hex.includes("06" + (oid.length / 2).toString(16).padStart(2, "0") + oid)) return name;
  return null;
}

// Signature bytes from SD per SE (hex default, or base64).
export function decodeSignature(SD, SE) {
  if (SE === "hex") return hexToBytes(SD);
  if (SE === "base64") return b64ToBytes(SD);
  return null;
}

// SubjectPublicKeyInfo for a bare uncompressed point on a named curve.
export function buildSpki(curve, point) {
  const oid = Object.keys(CURVE_OIDS).find((k) => CURVE_OIDS[k] === curve);
  if (!oid) return null;
  const tlv = (tag, body) => {
    const l = body.length;
    const len = l < 0x80 ? [l] : l < 0x100 ? [0x81, l] : [0x82, l >> 8, l & 0xff];
    return Uint8Array.from([tag, ...len, ...body]);
  };
  const algo = tlv(0x30, [...tlv(0x06, hexToBytes("2a8648ce3d0201")), ...tlv(0x06, hexToBytes(oid))]);
  return tlv(0x30, [...algo, ...tlv(0x03, [0, ...point])]);
}

// DER ECDSA-Sig-Value -> fixed-width r||s (WebCrypto wants this form). null if not strict DER.
export function derToRaw(der, size) {
  let i = 0;
  if (der[i++] !== 0x30) return null;
  let len = der[i++];
  if (len & 0x80) { if (len !== 0x81) return null; len = der[i++]; }
  if (i + len !== der.length) return null;
  const int = () => {
    if (der[i++] !== 0x02) return null;
    const l = der[i++];
    let v = der.slice(i, i + l); i += l;
    if (v.length !== l || !l) return null;
    while (v.length > 1 && v[0] === 0) v = v.slice(1);
    if (v.length > size) return null;
    const out = new Uint8Array(size); out.set(v, size - v.length); return out;
  };
  const r = int(); if (!r) return null;
  const s = int(); if (!s) return null;
  if (i !== der.length) return null;
  const raw = new Uint8Array(size * 2); raw.set(r); raw.set(s, size); return raw;
}
