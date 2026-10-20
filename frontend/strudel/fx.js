// Live-FX in Echtzeit: Das gespielte Programm endet mit .withValue(v => grooveFx.apply(v)).
// Strudel ruft das beim Einplanen jedes Ereignisses auf (~0,1 s voraus), Regler und
// Halte-Effekte wirken deshalb sofort – ohne das Programm neu auszuwerten.
const logHz = (lo, hi, t) => Math.round(lo * (hi / lo) ** t);
const max = (a, b) => Math.max(a ?? 0, b);

export const HOLDS = [
  { key: "echo", label: "Echo-Out", hint: "1" },
  { key: "wash", label: "Reverb-Wash", hint: "2" },
  { key: "drive", label: "Distortion-Riser", hint: "3" },
  { key: "phaser", label: "Phaser", hint: "4" },
  { key: "stutter", label: "Beat-Stutter", hint: "5" },
  { key: "crush", label: "Bitcrush", hint: "6" },
];

// Bipolarer DJ-Filter: -100..0 Low-Pass (dumpf), 0..100 High-Pass (dünn)
export const lowpassHz = f => logHz(150, 20000, 1 + f / 100);
export const highpassHz = f => logHz(30, 6000, f / 100);

export function createFx(state) {
  const held = {}; // Effekt -> Startzeit; Riser und Stutter steigern sich mit der Haltedauer
  const secs = key => (held[key] ? (performance.now() - held[key]) / 1000 : 0);

  function apply(v) {
    const m = state.macro;
    const o = { ...v };
    if (m.filter < -2) { o.cutoff = Math.min(v.cutoff ?? 20000, lowpassHz(m.filter)); o.resonance = max(v.resonance, 5); }
    if (m.filter > 2) { o.hcutoff = max(v.hcutoff, highpassHz(m.filter)); o.hresonance = max(v.hresonance, 5); }
    const space = held.wash ? 1 : m.space / 100;
    if (space) { o.room = max(v.room, space * 0.9); o.roomsize = max(v.roomsize, held.wash ? 10 : 1 + space * 4); }
    const echo = held.echo ? 1 : m.echo / 100;
    if (echo) {
      o.delay = max(v.delay, echo * (held.echo ? 0.9 : 0.7));
      o.delaytime = (60 / state.bpm) * 0.75;
      o.delayfeedback = held.echo ? 0.8 : 0.45;
    }
    const drive = held.drive ? Math.min(0.95, 0.3 + secs("drive") * 0.15) : (m.drive / 100) * 0.7;
    if (drive) o.shape = max(v.shape, drive);
    if (held.phaser) { o.phaserrate = 0.5; o.phaserdepth = 0.9; }
    if (held.crush) { o.crush = 4; o.coarse = 6; }
    o.postgain = (v.postgain ?? 1) * (m.volume / 100) * 1.1;
    return o;
  }

  // Beat-Stutter wird beim Halten dichter: 2x, nach 1 s 4x, nach 2 s 8x
  const ply = () => (!held.stutter ? 1 : secs("stutter") < 1 ? 2 : secs("stutter") < 2 ? 4 : 8);

  window.grooveFx = { apply, ply };
  return {
    press: key => { held[key] ??= performance.now(); },
    release: key => { delete held[key]; },
  };
}
