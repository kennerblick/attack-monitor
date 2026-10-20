// Strudel Groove Machine: baut aus Genre, Spuren und Reglern ein Strudel-Programm und spielt es ab.
// Jede Änderung erzeugt den Code neu und wird live (am Zyklusende) übernommen.
import { GENRES, LAYERS, KEYS } from "./genres.js";
import { buildCode } from "./code.js";

const $ = id => document.getElementById(id);
const SAMPLE_BANKS = [
  "github:tidalcycles/dirt-samples",
  "https://raw.githubusercontent.com/felixroos/dough-samples/main/tidal-drum-machines.json",
  "https://raw.githubusercontent.com/felixroos/dough-samples/main/piano.json",
];

const state = {
  genre: GENRES[0], key: GENRES[0].key0, on: new Set(GENRES[0].on), playing: false, ready: false,
  macro: { filter: 100, space: 25, echo: 20, drive: 0, volume: 80 }, bpm: GENRES[0].bpm,
};

let timer = null;
let audioReady = null;
function apply() {
  const code = buildCode(state);
  $("code").textContent = code;
  if (!state.playing) return;
  clearTimeout(timer);
  timer = setTimeout(() => window.evaluate(code).catch(err => showStatus(`Pattern-Fehler: ${err.message}`, "bad")), 120);
}

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
    audioReady ||= window.initAudio();
    await audioReady;
    await window.getAudioContext().resume();
    apply();
    showStatus(`▶ ${state.genre.name} · ${state.key} ${state.genre.scale} · ${state.bpm} BPM`, "ok");
  } else {
    window.hush();
    showStatus("Gestoppt");
  }
}

function selectGenre(g) {
  Object.assign(state, { genre: g, key: g.key0, bpm: g.bpm, on: new Set(g.on) });
  $("bpm").value = g.bpm;
  render();
  apply();
  if (state.playing) showStatus(`▶ ${g.name} · ${state.key} ${g.scale} · ${g.bpm} BPM`, "ok");
}

function toggleLayer(key) {
  state.on.has(key) ? state.on.delete(key) : state.on.add(key);
  render();
  apply();
}

function render() {
  document.documentElement.style.setProperty("--genre", state.genre.color);
  $("genres").innerHTML = GENRES.map(g =>
    `<button class="genre" data-key="${g.key}" aria-pressed="${g === state.genre}" style="--c:${g.color}"><b>${g.name}</b><small>${g.bpm} BPM</small></button>`).join("");
  $("genres").querySelectorAll("button").forEach(b => { b.onclick = () => selectGenre(GENRES.find(g => g.key === b.dataset.key)); });
  $("pads").innerHTML = LAYERS.map(l =>
    `<button class="pad" data-key="${l.key}" aria-pressed="${state.on.has(l.key)}"><b>${l.label}</b><kbd>${l.hint}</kbd></button>`).join("");
  $("pads").querySelectorAll("button").forEach(b => { b.onclick = () => toggleLayer(b.dataset.key); });
  $("keys").innerHTML = KEYS.map(k => `<button data-k="${k}" aria-pressed="${k === state.key}">${k}</button>`).join("");
  $("keys").querySelectorAll("button").forEach(b => { b.onclick = () => { state.key = b.dataset.k; render(); apply(); }; });
  $("bpm-out").textContent = state.bpm;
}

function bindMacros() {
  document.querySelectorAll("[data-macro]").forEach(input => {
    const out = input.parentElement.querySelector("output");
    const update = () => {
      state.macro[input.dataset.macro] = Number(input.value);
      input.style.setProperty("--v", input.value);
      out.textContent = `${input.value}%`;
    };
    input.addEventListener("input", () => { update(); apply(); });
    update();
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

const SHORTCUTS = Object.fromEntries(LAYERS.map(l => [l.hint.toLowerCase(), l.key]));
addEventListener("keydown", e => {
  if (e.target.matches("input, textarea")) return;
  if (e.code === "Space") { e.preventDefault(); togglePlay(); }
  else if (SHORTCUTS[e.key.toLowerCase()]) toggleLayer(SHORTCUTS[e.key.toLowerCase()]);
});

$("play").onclick = togglePlay;
$("copy").onclick = () => navigator.clipboard.writeText(buildCode(state));
$("repl").onclick = () => {
  const code = buildCode(state);
  window.open(`https://strudel.cc/#${btoa(unescape(encodeURIComponent(code)))}`, "_blank", "noopener");
};

render();
bindMacros();
apply();
drawScope();
showStatus("Lade Samples …");
window.initStrudel({ prebake: () => Promise.all(SAMPLE_BANKS.map(b => window.samples(b))) })
  .then(() => { state.ready = true; showStatus("Bereit: Play drücken oder Leertaste", "ok"); })
  .catch(err => showStatus(`Audio-Engine konnte nicht starten: ${err.message}`, "bad"));
