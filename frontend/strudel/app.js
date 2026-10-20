// Strudel Groove Machine: baut aus Genre, Variante, Spuren und Reglern ein Strudel-Programm und spielt es ab.
// Genre/Variante/Spur/Tonart/Tempo erzeugen den Code neu; Regler und Live-FX wirken in Echtzeit (fx.js).
import { GENRES, KEYS, PAD_KEYS } from "./genres/index.js";
import { buildCode } from "./code.js";
import { createLiveView } from "./live.js";
import { createFx, HOLDS } from "./fx.js";

const $ = id => document.getElementById(id);
const SAMPLE_BANKS = [
  "github:tidalcycles/dirt-samples",
  "https://raw.githubusercontent.com/felixroos/dough-samples/main/tidal-drum-machines.json",
  "https://raw.githubusercontent.com/felixroos/dough-samples/main/piano.json",
];

const state = {
  genre: GENRES[0], variant: GENRES[0].variants[0], key: "A", on: new Set(), bpm: 120, playing: false, ready: false,
  macro: { filter: 0, space: 25, echo: 20, drive: 0, volume: 80 },
};
const fx = createFx(state);

let timer = null;
let audioReady = null;
let repl = null; // von initStrudel; repl.stop() hält den Scheduler wirklich an
let suspendTimer = null;
let pattern = null; // zuletzt ausgewertetes Pattern, für die Live-Markierung
const live = createLiveView({
  code: $("code"), bar: $("bar"), beats: $("beats"), cycle: $("cycle"),
  ignore: text => text === state.variant.bank || text.includes(":"),
});

function apply() {
  clearTimeout(timer);
  if (!state.playing) { pattern = null; live.show(buildCode(state)); return; }
  timer = setTimeout(async () => {
    const result = await repl.evaluate(buildCode(state, { live: true }));
    // Stopp während der Auswertung: evaluate hat den Scheduler gerade (wieder) gestartet
    if (!state.playing) { repl.stop(); return; }
    if (result) { pattern = result; live.show(buildCode(state), pattern, repl.scheduler); }
  }, 120);
}

// Regler ändern nur die Anzeige; der Klang folgt über grooveFx sofort
const refreshCode = () => live.show(buildCode(state), pattern, pattern && repl.scheduler);
const playingText = () => `▶ ${state.genre.name} · ${state.variant.name} · ${state.key} ${state.variant.scale} · ${state.bpm} BPM`;

function showStatus(text, cls = "") {
  $("status").textContent = text;
  $("status").className = `status ${cls}`;
}

async function togglePlay() {
  if (!state.ready) { showStatus("Samples werden noch geladen …"); return; }
  state.playing = !state.playing;
  $("play").classList.toggle("on", state.playing);
  $("play").setAttribute("aria-label", state.playing ? "Stopp" : "Play");
  if (state.playing) {
    // Worklets explizit laden, bevor die ersten Töne starten (sonst Race mit initAudioOnFirstClick)
    clearTimeout(suspendTimer);
    audioReady ||= window.initAudio();
    await audioReady;
    await window.getAudioContext().resume();
    apply();
    showStatus(playingText(), "ok");
  } else {
    // Nicht window.hush(): das globale hush wird nach dem ersten evaluate durch eine Variante
    // ersetzt, die nur die Pattern-Liste leert – der Scheduler spielt dann weiter.
    clearTimeout(timer);
    repl.stop();
    // Hall und Echo würden sonst noch Sekunden nachklingen: kurz ausklingen lassen, dann anhalten
    suspendTimer = setTimeout(() => window.getAudioContext().suspend(), 300);
    apply();
    showStatus("Gestoppt");
  }
}

function selectVariant(genre, variant) {
  Object.assign(state, { genre, variant, key: variant.key0, bpm: variant.bpm, on: new Set(variant.on) });
  $("bpm").value = variant.bpm;
  render();
  apply();
  if (state.playing) showStatus(playingText(), "ok");
}

function toggleLayer(key) {
  state.on.has(key) ? state.on.delete(key) : state.on.add(key);
  render();
  apply();
}

function render() {
  document.documentElement.style.setProperty("--genre", state.genre.color);
  $("genres").innerHTML = GENRES.map(g =>
    `<button class="genre" data-key="${g.key}" aria-pressed="${g === state.genre}" style="--c:${g.color}"><b>${g.name}</b><small>${g.variants.length} Varianten</small></button>`).join("");
  $("genres").querySelectorAll("button").forEach(b => {
    b.onclick = () => { const g = GENRES.find(x => x.key === b.dataset.key); selectVariant(g, g.variants[0]); };
  });
  $("variants-title").textContent = state.genre.name;
  $("variants").innerHTML = state.genre.variants.map(v =>
    `<button class="variant" data-key="${v.key}" aria-pressed="${v === state.variant}"><b>${v.name}</b>` +
    `<small>${v.bpm} BPM · ${v.key0} ${v.scale}</small><span>${v.desc}</span></button>`).join("");
  $("variants").querySelectorAll("button").forEach(b => {
    b.onclick = () => selectVariant(state.genre, state.genre.variants.find(v => v.key === b.dataset.key));
  });
  $("pads").innerHTML = state.genre.tracks.map((t, i) =>
    `<button class="pad" data-key="${t.key}" aria-pressed="${state.on.has(t.key)}"><b>${t.label}</b><kbd>${PAD_KEYS[i].toUpperCase()}</kbd></button>`).join("");
  $("pads").querySelectorAll("button").forEach(b => { b.onclick = () => toggleLayer(b.dataset.key); });
  $("keys").innerHTML = KEYS.map(k => `<button data-k="${k}" aria-pressed="${k === state.key}">${k}</button>`).join("");
  $("keys").querySelectorAll("button").forEach(b => { b.onclick = () => { state.key = b.dataset.k; render(); apply(); }; });
  $("bpm-out").textContent = state.bpm;
}

function bindMacros() {
  document.querySelectorAll("[data-macro]").forEach(input => {
    const out = input.parentElement.querySelector("output");
    const update = () => {
      const v = Number(input.value);
      state.macro[input.dataset.macro] = v;
      out.textContent = input.dataset.macro !== "filter" ? `${v}%`
        : Math.abs(v) <= 2 ? "offen" : v < 0 ? `LP ${-v}%` : `HP ${v}%`;
    };
    input.addEventListener("input", () => { update(); refreshCode(); });
    update();
  });
  // Doppelklick setzt den DJ-Filter auf die Mitte zurück
  document.querySelector("[data-macro=filter]").addEventListener("dblclick", e => {
    e.target.value = 0; e.target.dispatchEvent(new Event("input"));
  });
  $("bpm").addEventListener("input", e => { state.bpm = Number(e.target.value); $("bpm-out").textContent = state.bpm; apply(); });
}

function drawScope() {
  const canvas = $("scope");
  const ctx = canvas.getContext("2d");
  const loop = () => {
    const w = canvas.width = canvas.clientWidth * devicePixelRatio;
    const h = canvas.height = canvas.clientHeight * devicePixelRatio;
    ctx.clearRect(0, 0, w, h);
    const data = state.playing && state.ready ? window.getAnalyzerData("frequency", 1) : null;
    const bins = 64;
    const color = getComputedStyle(document.documentElement).getPropertyValue("--genre").trim() || "#4fd1ff";
    for (let i = 0; i < bins; i++) {
      // logarithmische Frequenzachse: Bässe bekommen mehr Platz
      const idx = data ? Math.floor((data.length * 0.6) ** (i / bins)) : 0;
      const db = data ? data[idx] : -140;
      const v = Math.max(0.02, Math.min(1, (db + 110) / 80));
      const bw = w / bins;
      ctx.fillStyle = color;
      ctx.globalAlpha = 0.35 + v * 0.65;
      ctx.fillRect(i * bw + 1, h - v * h, bw - 2, v * h);
    }
    requestAnimationFrame(loop);
  };
  loop();
}

// Live-FX wirken, solange Taste oder Knopf gehalten werden
function bindHolds() {
  $("holds").innerHTML = HOLDS.map(h => `<button class="hold" data-fx="${h.key}"><b>${h.label}</b><kbd>${h.hint}</kbd></button>`).join("");
  $("holds").querySelectorAll("button").forEach(b => {
    const on = e => { e.preventDefault(); b.setPointerCapture?.(e.pointerId); b.classList.add("on"); fx.press(b.dataset.fx); };
    const off = () => { b.classList.remove("on"); fx.release(b.dataset.fx); };
    b.addEventListener("pointerdown", on);
    ["pointerup", "pointercancel", "lostpointercapture"].forEach(ev => b.addEventListener(ev, off));
  });
}
const holdButton = key => $("holds").querySelector(`[data-fx="${HOLDS.find(h => h.hint === key)?.key}"]`);

addEventListener("keydown", e => {
  if (e.target.matches("input, textarea") || e.ctrlKey || e.metaKey || e.altKey) return;
  const key = e.key.toLowerCase();
  if (e.code === "Space") { e.preventDefault(); togglePlay(); }
  else if (holdButton(key)) { if (!e.repeat) { holdButton(key).classList.add("on"); fx.press(holdButton(key).dataset.fx); } }
  else if (PAD_KEYS.includes(key) && !e.repeat) {
    const track = state.genre.tracks[PAD_KEYS.indexOf(key)];
    if (track) toggleLayer(track.key);
  }
});
addEventListener("keyup", e => {
  const b = holdButton(e.key.toLowerCase());
  if (b) { b.classList.remove("on"); fx.release(b.dataset.fx); }
});

$("play").onclick = togglePlay;
$("copy").onclick = () => navigator.clipboard.writeText(buildCode(state));
$("repl").onclick = () => {
  const code = buildCode(state);
  window.open(`https://strudel.cc/#${btoa(unescape(encodeURIComponent(code)))}`, "_blank", "noopener");
};

selectVariant(GENRES[0], GENRES[0].variants[0]);
bindMacros();
bindHolds();
drawScope();
showStatus("Lade Samples …");
window.initStrudel({
  prebake: () => Promise.all(SAMPLE_BANKS.map(b => window.samples(b))),
  onEvalError: err => showStatus(`Pattern-Fehler: ${err.message}`, "bad"),
})
  .then(r => { repl = r; state.ready = true; showStatus("Bereit: Play drücken oder Leertaste", "ok"); })
  .catch(err => showStatus(`Audio-Engine konnte nicht starten: ${err.message}`, "bad"));
