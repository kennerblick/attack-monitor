// Erzeugt aus dem Bedienzustand ein Strudel-Programm (reine Funktion, ohne DOM).
import { LAYERS } from "./genres.js";

// Regler 0..100 -> Strudel-Werte
const filterHz = v => Math.round(120 * (20000 / 120) ** (v / 100));

export function buildCode(s) {
  const fill = code => code.replaceAll("{K}", s.key).replaceAll("{S}", s.genre.scale).replaceAll("{B}", s.genre.bank);
  const layers = LAYERS.filter(l => s.on.has(l.key)).map(l => `  ${fill(s.genre.layers[l.key])}`);
  if (!layers.length) return "silence";
  const m = s.macro;
  const fx = [
    m.filter < 100 ? `.lpf(${filterHz(m.filter)})` : "",
    m.space ? `.room(${(m.space / 100 * 0.9).toFixed(2)}).roomsize(${(1 + m.space / 25).toFixed(1)})` : "",
    m.echo ? `.delay(${(m.echo / 100 * 0.7).toFixed(2)}).delaytime(${(60 / s.bpm * 0.75).toFixed(3)}).delayfeedback(.45)` : "",
    m.drive ? `.shape(${(m.drive / 100 * 0.7).toFixed(2)})` : "",
  ].join("");
  return `setcpm(${s.bpm}/4)\n\nstack(\n${layers.join(",\n")}\n)${fx}.postgain(${(m.volume / 100 * 1.1).toFixed(2)}).analyze(1)`;
}
