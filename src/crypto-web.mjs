// Browser adapter (WebCrypto). WebCrypto only has the NIST curves, so secp256k1, the
// 192-bit curves and brainpool are reported as unsupported here; the Node CLI checks them.
import { ALGORITHMS, derToRaw } from "./keys.mjs";

const WEB = { secp256r1: "P-256", secp384r1: "P-384" };

export const webCrypto = {
  name: "webcrypto",
  supports: (curve) => curve in WEB,
  async verify({ curve, hash, spki, data, sigDer }) {
    const size = Object.values(ALGORITHMS).find((a) => a.curve === curve).size;
    const raw = derToRaw(sigDer, size);
    if (!raw) return false;
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: WEB[curve] }, false, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash }, key, raw, data);
  },
};
