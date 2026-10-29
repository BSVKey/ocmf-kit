// Node crypto adapter. OpenSSL covers every curve in OCMF Table 22, brainpool included.
import { createPublicKey, generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from "node:crypto";

const OPENSSL = {
  secp192k1: "secp192k1",
  secp256k1: "secp256k1",
  secp192r1: "prime192v1",
  secp256r1: "prime256v1",
  brainpool256r1: "brainpoolP256r1",
  secp384r1: "secp384r1",
  brainpool384r1: "brainpoolP384r1",
};
const HASH = { "SHA-256": "sha256", "SHA-384": "sha384" };

export const nodeCrypto = {
  name: "node",
  supports: (curve) => curve in OPENSSL,
  async verify({ hash, spki, data, sigDer }) {
    const key = createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
    return nodeVerify(HASH[hash], Buffer.from(data), { key, dsaEncoding: "der" }, Buffer.from(sigDer));
  },
};

// { privateKey, spki } for a fresh key on an OCMF curve.
export function generateKey(curve = "secp256r1") {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: OPENSSL[curve] });
  return { curve, privateKey, spki: new Uint8Array(publicKey.export({ format: "der", type: "spki" })) };
}

export const signDer = (privateKey, data, hash = "SHA-256") =>
  new Uint8Array(nodeSign(HASH[hash], Buffer.from(data), { key: privateKey, dsaEncoding: "der" }));
