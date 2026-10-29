# ocmf-kit

Generate and check **OCMF** signed meter readings, the format German EV charging stations use to sign the kWh they bill (Eichrecht).

- **A simulated signing meter** that writes real, verifiable OCMF 1.4 records, plus 13 ways a record can be wrong (tampered, wrong key, replayed page, missing page, swapped meter, and more), so a charging backend's *rejection* path can be tested.
- **A session checker** that follows the OCMF verification rules: every signature valid, same meter throughout, pages continuous with no repeats or gaps, a start and an end reading, no error states, meter counts never going down. It reports the energy delivered with exact decimals and can compare it with the billed amount.
- **OCPP mappings**: a 1.6 `SampledValue` with `format: "SignedData"`, and a 2.0.1 / 2.1 `SignedMeterValueType` (`signedMeterData`, `signingMethod`, `encodingMethod`, `publicKey`), and back.
- **A browser checker** (`web/`) for drivers. Nothing is uploaded, and every field is shown as plain text.

Zero dependencies. Node 18+ and modern browsers.

> This simulates the wire format. It is not a calibrated meter, its output is not legally valid metering data, and the checker is not the officially approved transparency software.

## Use

```bash
node bin/ocmf.mjs modes                                   # list the test modes
node bin/ocmf.mjs gen --mode valid > session.ocmf         # prints the public key on stderr
node bin/ocmf.mjs gen --mode tampered_payload --ocpp 2.0.1
node bin/ocmf.mjs check session.ocmf --key <hex|base64|PEM or key file> --billed 7.825
npm test
npm run fixtures                                          # rewrite fixtures/
```

```js
import { createMeter, chargingSession, checkSession, nodeCrypto, toOcpp2SignedMeterValue } from "@bsvkey/ocmf-kit";

const meter = createMeter();                                  // ECDSA-secp256r1-SHA256 by default
const { records, publicKey } = chargingSession(meter, { mode: "valid", format: "SR" });
const result = await checkSession(records, publicKey, nodeCrypto);
// { ok: true, energy: { delivered: "7.825", unit: "kWh", ... }, problems: [], warnings: [] }
const smv = toOcpp2SignedMeterValue(records[0], meter.key.spki);   // for TransactionEventRequest
```

## Test modes

| Mode | A checker should |
|---|---|
| `valid` | accept |
| `tampered_payload` | reject: a reading changed after signing |
| `wrong_key` | reject: signed by a different key than the one advertised |
| `invalid_signature` | reject: garbage signature block |
| `replayed_page` | reject: same page number twice |
| `missing_page` | reject: a record in the middle is gone |
| `meter_swapped` | reject: end record from another meter |
| `register_backwards` | reject: end reading below start |
| `energy_error_flag` | reject: meter flagged energy unusable (`EF: "E"`) |
| `meter_fault` | reject: meter status not `G` |
| `whitespace_changed` | reject: whitespace in the signed part changed |
| `number_reformatted` | reject: `1234.500` written as `1234.5000` |
| `unsynchronized_clock` | accept, with a warning |
| `hostile_text` | accept, while showing HTML/script in text fields as text |

The first four are the modes proposed in [shiv3/ocpp-cp-simulator#315](https://github.com/shiv3/ocpp-cp-simulator/issues/315). `fixtures/` holds one folder per mode and format with `records.ocmf`, `publicKey.hex` and `expected.json`, so a checker in any language can be tested against them.

## Notes

- **Signed bytes are the payload text exactly as received.** Numbers are never parsed into floats (OCMF counts `2935.600` and `2935.6` as different text), and whitespace changes break the signature, as the spec requires.
- **Curves.** Node checks every curve in OCMF Table 22 (secp256r1, secp384r1, secp256k1, secp192r1, secp192k1, brainpool256r1, brainpool384r1). Browsers have only P-256 and P-384 in WebCrypto, so the page says when a record needs the command-line checker.
- **Keys** can be PEM, hex or base64 DER, or a bare uncompressed point. Take the key from the charger label or a key register, never from the data being checked.
- Checked against third-party OCMF samples (SEAL AG / Carlo Gavazzi, and the Chargy test set): signatures agree.

## License

Apache-2.0. Copyright Embryo Space Inc. (DBA BSVKey).
