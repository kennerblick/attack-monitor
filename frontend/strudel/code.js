// Erzeugt aus dem Bedienzustand ein Strudel-Programm (reine Funktion, ohne DOM).
// display: lesbarer Code mit festen Werten (Anzeige, Kopieren, REPL).
// live: gleicher Anfang, aber Effekte über grooveFx (fx.js), damit Regler in Echtzeit wirken.
// Beide teilen den Text bis zum Ende von stack(...) – die Positionen für die Live-Markierung passen.
import { trackCode } from "./genres/index.js";
import { lowpassHz, highpassHz } from "./fx.js";

// Methodenkette auf oberster Ebene umbrechen: s("bd*4").bank("x") -> s("bd*4")\n    .bank("x")
function chain(code, indent) {
  let out = "", depth = 0, quote = null;
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (quote) { if (c === quote) quote = null; }
    else if (c === '"' || c === "'") quote = c;
    else if (c === "(" || c === "[") depth++;
    else if (c === ")" || c === "]") depth--;
    else if (c === "." && depth === 0 && code[i - 1] === ")") { out += `\n${indent}`; }
    out += c;
  }
  return out;
}

function displayFx(s) {
  const m = s.macro;
  return [
    m.filter < -2 ? `.lpf(${lowpassHz(m.filter)})` : "",
    m.filter > 2 ? `.hpf(${highpassHz(m.filter)})` : "",
    m.space ? `.room(${(m.space / 100 * 0.9).toFixed(2)}).roomsize(${(1 + m.space / 25).toFixed(1)})` : "",
    m.echo ? `.delay(${(m.echo / 100 * 0.7).toFixed(2)}).delaytime(${(60 / s.bpm * 0.75).toFixed(3)}).delayfeedback(.45)` : "",
    m.drive ? `.shape(${(m.drive / 100 * 0.7).toFixed(2)})` : "",
    `.postgain(${(m.volume / 100 * 1.1).toFixed(2)})`,
  ].filter(Boolean);
}

export function buildCode(s, { live = false } = {}) {
  const v = s.variant;
  const fill = code => code.replaceAll("{K}", s.key).replaceAll("{S}", v.scale).replaceAll("{B}", v.bank);
  const layers = s.genre.tracks.filter(t => s.on.has(t.key))
    .map(t => `  ${chain(fill(trackCode(s.genre, v, t.key)), "    ")}`);
  if (!layers.length) return "silence";
  const fx = live
    ? [".ply(ref(() => grooveFx.ply()))", ".withValue(v => grooveFx.apply(v))"]
    : displayFx(s);
  return `setcpm(${s.bpm}/4)\n\nstack(\n${layers.join(",\n")}\n)\n  ${[...fx, ".analyze(1)"].join("\n  ")}`;
}
