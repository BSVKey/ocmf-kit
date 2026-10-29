// Exact decimal arithmetic on number text, so 1241.925 - 1234.1 is 7.825 and not 7.82499999.
const split = (s) => {
  const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(String(s).trim());
  if (!m) return null;
  return { neg: m[1] === "-", int: m[2], frac: m[3] || "" };
};

const toScaled = (p, scale) => {
  const n = BigInt(p.int + p.frac.padEnd(scale, "0"));
  return p.neg ? -n : n;
};

export const isDecimal = (s) => split(s) !== null;

// Compare two decimal strings: -1, 0 or 1 (null if either is not a plain decimal).
export function cmp(a, b) {
  const x = split(a), y = split(b);
  if (!x || !y) return null;
  const scale = Math.max(x.frac.length, y.frac.length);
  const d = toScaled(x, scale) - toScaled(y, scale);
  return d < 0n ? -1 : d > 0n ? 1 : 0;
}

// a - b, written with as many decimal places as the more precise input.
export function sub(a, b) {
  const x = split(a), y = split(b);
  if (!x || !y) return null;
  const scale = Math.max(x.frac.length, y.frac.length);
  let d = toScaled(x, scale) - toScaled(y, scale);
  const neg = d < 0n; if (neg) d = -d;
  const s = d.toString().padStart(scale + 1, "0");
  const out = scale ? `${s.slice(0, -scale)}.${s.slice(-scale)}` : s;
  return (neg ? "-" : "") + out;
}
