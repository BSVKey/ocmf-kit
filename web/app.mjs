// Page logic. Every value from the data is written with textContent, never as HTML:
// OCMF fields are free text chosen by whoever produced the record.
import { checkSession, EXPLAIN, webCrypto, fromOcpp, publicKeyFromOcpp2 } from "../src/web.mjs";

const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = String(text); if (cls) e.className = cls; return e; };

function recordsFrom(text) {
  const t = text.trim();
  if (t.startsWith("[") || t.startsWith("{")) {
    try {
      const v = JSON.parse(t);
      return (Array.isArray(v) ? v : [v]).map((x) => ({ ocmf: fromOcpp(x), key: publicKeyFromOcpp2(x) })).filter((x) => x.ocmf);
    } catch { /* fall through to plain text */ }
  }
  return t.split(/(?=^OCMF\|)/m).map((s) => ({ ocmf: s.trim(), key: null })).filter((x) => x.ocmf);
}

function row(table, k, v) { const tr = el("tr"); tr.append(el("th", k), el("td", v ?? "—")); table.append(tr); }

async function run() {
  const recs = recordsFrom($("data").value);
  const key = $("key").value.trim();
  const billed = $("billed").value.trim().replace(",", ".");
  $("out").hidden = false;
  const v = $("verdict"), next = $("next"), probs = $("problems"), facts = $("facts"), table = $("recs");
  probs.replaceChildren(); facts.replaceChildren(); table.replaceChildren();
  if (!recs.length) { v.className = "verdict bad"; v.textContent = "No signed readings found"; next.textContent = "Paste the data from step 1. Each record starts with OCMF|."; return; }
  if (!key) {
    v.className = "verdict bad"; v.textContent = "Public key needed";
    const carried = recs.find((r) => r.key);
    next.textContent = carried ? "The data carries a key, but a key from the same source proves nothing. Paste the key from the charger label or operator list in step 2." : "Paste the meter's public key in step 2.";
    return;
  }
  const r = await checkSession(recs.map((x) => x.ocmf), key, webCrypto, billed ? { billedEnergy: billed } : {});
  v.className = `verdict ${r.ok ? "good" : "bad"}`;
  v.textContent = r.ok ? `Genuine: ${r.energy ? `${r.energy.delivered} ${r.energy.unit ?? ""} signed by the meter` : "signatures check out"}` : "Do not rely on this receipt";
  next.textContent = r.ok
    ? (billed ? "The billed energy matches what the meter signed." : "Compare this energy with your bill, or enter the billed amount in step 3.")
    : "Ask the operator for the original signed data. If the problem stays, contact your local calibration authority (Eichamt).";
  for (const p of r.problems) probs.append(el("li", `${EXPLAIN[p.code] ?? p.code}${p.record != null ? ` (record ${p.record + 1})` : ""}${p.detail ? `: ${p.detail}` : ""}`, "bad"));
  for (const w of r.warnings) probs.append(el("li", `Note: ${EXPLAIN[w.code] ?? w.code}${w.record != null ? ` (record ${w.record + 1})` : ""}`, "warn"));

  const m = r.meter ?? {};
  row(facts, "Meter", [m.vendor, m.model].filter(Boolean).join(" ") || null);
  row(facts, "Meter serial", m.serial);
  row(facts, "Charging station", [m.gateway, m.gatewaySerial].filter(Boolean).join(", ") || null);
  if (r.energy) {
    row(facts, r.ok ? "Energy delivered" : "Energy claimed (not proven)", `${r.energy.delivered} ${r.energy.unit ?? ""}`);
    row(facts, "Meter at start", `${r.energy.begin} at ${r.energy.beginTime}`);
    row(facts, "Meter at end", `${r.energy.end} at ${r.energy.endTime}`);
    if (r.energy.cableLoss) row(facts, "Cable loss deducted", r.energy.cableLoss);
  }
  if (r.identification) row(facts, "Customer identification", [r.identification.type, r.identification.id, r.identification.level].filter(Boolean).join(" · "));
  for (const x of r.records) row(table, `Record ${x.index + 1}${x.page ? ` (${x.page})` : ""}`, x.ok ? "Signature good" : EXPLAIN[x.reason] ?? x.reason);
}

$("check").addEventListener("click", () => run().catch((e) => { $("out").hidden = false; $("verdict").className = "verdict bad"; $("verdict").textContent = "Could not check"; $("next").textContent = e.message; }));

// Examples from ../fixtures (made by scripts/make-fixtures.mjs).
fetch("../fixtures/manifest.json").then((r) => (r.ok ? r.json() : [])).then((list) => {
  const sel = $("sample");
  for (const f of list) {
    const o = el("option", `${f.format === "MR" ? "One record" : "Two records"}: ${f.mode.replaceAll("_", " ")} (${f.valid ? "should pass" : "should fail"})`);
    o.value = f.dir; sel.append(o);
  }
  sel.addEventListener("change", async () => {
    if (!sel.value) return;
    const [d, k] = await Promise.all([fetch(`../fixtures/${sel.value}/records.ocmf`).then((r) => r.text()), fetch(`../fixtures/${sel.value}/publicKey.hex`).then((r) => r.text())]);
    $("data").value = d.trim(); $("key").value = k.trim(); $("billed").value = "";
    run();
  });
}).catch(() => {});
