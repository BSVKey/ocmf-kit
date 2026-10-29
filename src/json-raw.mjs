// JSON that keeps numbers exactly as written.
// OCMF says a reading value's text (2935.600, not 2935.6) is part of the measurement, so a
// verifier must never round-trip numbers through a float. parse() returns plain objects,
// arrays, strings, booleans and null, with every number as a Num holding its source text.
export class Num {
  constructor(raw) { this.raw = raw; }
  toString() { return this.raw; }
  toJSON() { return Number(this.raw); }
}

export const numText = (v) => (v instanceof Num ? v.raw : typeof v === "string" ? v : v == null ? null : String(v));

export function parse(text) {
  let i = 0;
  const err = (m) => { throw new SyntaxError(`${m} at ${i}`); };
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const value = () => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; const o = {}; ws();
      if (text[i] === "}") { i++; return o; }
      for (;;) {
        ws(); if (text[i] !== '"') err("expected key");
        const k = str();
        if (Object.prototype.hasOwnProperty.call(o, k)) err(`duplicate key ${k}`);
        ws(); if (text[i++] !== ":") err("expected :");
        o[k] = value(); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return o; }
        err("expected , or }");
      }
    }
    if (c === "[") {
      i++; const a = []; ws();
      if (text[i] === "]") { i++; return a; }
      for (;;) {
        a.push(value()); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return a; }
        err("expected , or ]");
      }
    }
    if (c === '"') return str();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i));
    if (!m) err("unexpected character");
    i += m[0].length;
    return new Num(m[0]);
  };
  const str = () => {
    const m = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(text.slice(i));
    if (!m) err("bad string");
    i += m[0].length;
    return JSON.parse(m[0]);
  };
  const v = value(); ws();
  if (i !== text.length) err("trailing data");
  return v;
}

// Compact JSON writer that emits Num exactly as held.
export function stringify(v) {
  if (v instanceof Num) return v.raw;
  if (Array.isArray(v)) return `[${v.map(stringify).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => `${JSON.stringify(k)}:${stringify(x)}`).join(",")}}`;
  return JSON.stringify(v);
}
