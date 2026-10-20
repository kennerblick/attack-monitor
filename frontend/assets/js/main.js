// Steuerung: holt Feed (2 s), Statistik (15 s) und Status (30 s) und verteilt sie auf Globus und Panels.
import { createGlobe } from "./globe.js";
import { renderKpis, renderTypes, renderLists, renderFeed, renderDetail, toast } from "./panels.js";
import { renderTimeline, renderHeatmap } from "./charts.js";

const state = { range: "24h", active: null, events: [], lastId: 0, stats: null, status: null, lastOk: 0, lastFresh: 0 };
const REPLAY_AFTER = 6000; // ms ohne neuen Angriff, ab dann werden die letzten echten wiederholt
let globe = null;

const getJson = url => fetch(url, { cache: "no-store" }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });

function visible() {
  return state.active ? state.events.filter(e => state.active.has(e.type)) : state.events;
}

function redrawFeed(newIds = new Set()) {
  renderFeed(visible(), newIds, (ev, li) => {
    document.querySelectorAll("#feed li").forEach(x => x.removeAttribute("aria-selected"));
    li.setAttribute("aria-selected", "true");
    renderDetail(ev);
    if (ev.lat != null) globe?.focus(ev.lat, ev.lon);
  });
}

function redrawStats() {
  if (!state.stats) return;
  renderKpis(state.stats, null);
  renderTypes(state.stats, state.active, toggleType);
  renderLists(state.stats);
  renderTimeline(document.getElementById("timeline"), state.stats.timeline, state.active);
  renderHeatmap(document.getElementById("heatmap"), state.stats.heatmap);
  document.getElementById("tl-sub").textContent =
    { "1h": "letzte Stunde · je Minute", "24h": "24 Stunden · je 30 Min.", "7d": "7 Tage · je 3 Std." }[state.stats.range];
  globe?.setHotspots(state.stats.hotspots);
}

function toggleType(key) {
  const all = new Set(state.events.map(e => e.type).concat(state.stats.byType.map(t => t.type)));
  const next = new Set(state.active || all);
  next.has(key) ? next.delete(key) : next.add(key);
  state.active = next.size === 0 || next.size >= all.size ? null : next;
  globe?.setFilter(state.active);
  redrawStats();
  redrawFeed();
}

async function pollFeed() {
  try {
    const { events } = await getJson(`/api/feed?since=${state.lastId}`);
    state.lastOk = Date.now();
    if (events.length) {
      const fresh = state.lastId > 0;
      if (fresh) state.lastFresh = Date.now();
      // IDs sind beim Nachladen alter Logs nicht chronologisch: Merker = höchste ID, Anzeige nach Zeit
      state.lastId = Math.max(state.lastId, ...events.map(e => e.id));
      // Geo-Daten kommen asynchron nach: bekannte Events durch neuere Fassung ersetzen
      const byId = new Map(state.events.map(e => [e.id, e]));
      events.forEach(e => byId.set(e.id, e));
      state.events = [...byId.values()].sort((a, b) => b.ts - a.ts || b.id - a.id).slice(0, 80);
      // Älteste zuerst abspielen, verteilt über das Abfrageintervall
      [...events].sort((a, b) => a.ts - b.ts).forEach((ev, i, list) => setTimeout(() => {
        globe?.addAttack(ev);
        if (fresh && i === list.length - 1) toast(ev);
      }, fresh ? (i / list.length) * 1800 : i * 160));
      redrawFeed(fresh ? new Set(events.map(e => e.id)) : new Set());
    }
  } catch { /* Anzeige "stale" übernimmt tick() */ }
}

// In ruhigen Phasen die jüngsten echten Angriffe erneut als Bogen zeigen, damit der Globus lebt
function replay() {
  if (Date.now() - state.lastFresh < REPLAY_AFTER) return;
  const located = visible().filter(e => e.lat != null);
  if (located.length) globe?.addAttack(located[Math.floor(Math.random() * Math.min(located.length, 40))]);
}

async function refreshGeo() {
  // Events ohne Ort nachladen (Lookup läuft im Backend asynchron)
  const missing = state.events.filter(e => e.cc == null);
  if (!missing.length) return;
  const minId = Math.min(...missing.map(e => e.id)) - 1;
  try {
    const { events } = await getJson(`/api/feed?since=${minId}`);
    const byId = new Map(events.map(e => [e.id, e]));
    state.events = state.events.map(e => byId.get(e.id) || e);
    redrawFeed();
  } catch { /* nächster Versuch */ }
}

async function pollStats() {
  try { state.stats = await getJson(`/api/stats?range=${state.range}`); redrawStats(); } catch { /* später */ }
}

async function pollStatus() {
  try { state.status = await getJson("/api/status"); renderKpis(null, state.status); } catch { /* später */ }
  return state.status;
}

function tick() {
  const now = new Date();
  document.getElementById("clock").innerHTML =
    `<b>${now.toLocaleTimeString("de-DE")}</b> · UTC ${now.toISOString().slice(11, 19)}`;
  document.getElementById("live").classList.toggle("stale", Date.now() - state.lastOk > 15000);
}

document.querySelectorAll(".ranges button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".ranges button").forEach(x => x.setAttribute("aria-pressed", x === b));
  state.range = b.dataset.range;
  pollStats();
}));
addEventListener("resize", () => redrawStats());

(async function start() {
  setInterval(tick, 1000);
  tick();
  const status = await pollStatus();
  const server = status?.server || { lat: 52.52, lon: 13.4, name: "Berlin" };
  try {
    globe = await createGlobe(document.getElementById("globe"), server);
  } catch (err) {
    document.getElementById("globe").innerHTML = '<p class="empty" style="padding:24px">3D-Globus konnte nicht geladen werden (WebGL?).</p>';
    console.error(err);
  }
  await pollStats();
  await pollFeed();
  setInterval(pollFeed, 2000);
  setInterval(pollStats, 15000);
  setInterval(pollStatus, 30000);
  setInterval(refreshGeo, 6000);
  setInterval(replay, 1100);
})();
