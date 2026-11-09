// Sensoren: 3lis.de selbst und die Außensensoren (sensors.json auf dem Server). Jeder Sensor hat eine feste
// Farbe, die überall gleich bleibt: Karte, Feed-Plakette, Globus-Beschriftung und Einschlag-Ring.
import { num, esc } from "./format.js";

export const LOCAL = "3lis";
// Bewusst außerhalb der Typ-Palette (format.js), damit Sensor- und Angriffsfarben nicht verwechselt werden
const COLORS = ["#4fd1ff", "#ffb547", "#c792ff", "#7ee081"];

let sites = [{ name: LOCAL, label: "3lis.de" }];

// list: [{name, lat, lon, label, where?, lastPull?, interval?}], [0] = 3lis.de
export function setSensors(list) { sites = list.map((s, i) => ({ ...s, color: COLORS[i % COLORS.length] })); }
export const sensorSites = () => sites;
const site = name => sites.find(s => s.name === (name || LOCAL));
export const sensorName = name => site(name)?.label || name;
export const sensorColor = name => site(name)?.color || COLORS[0];
export const multiSensor = () => sites.length > 1;

export const sensorBadge = name =>
  `<span class="sb" style="--s:${sensorColor(name)}">${esc(sensorName(name))}</span>`;

const ago = ts => {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  return s < 90 ? `vor ${s} s` : s < 5400 ? `vor ${Math.round(s / 60)} min` : `vor ${Math.round(s / 3600)} h`;
};

// Zustand der Anbindung: 3lis.de ist immer lokal; Außensensoren nach dem letzten erfolgreichen Abruf
function health(s) {
  if (s.name === LOCAL) return ["ok", "lokal"];
  if (!s.lastPull) return ["warn", "noch kein Abruf"];
  const late = Date.now() / 1000 - s.lastPull;
  if (late < 3 * (s.interval || 60)) return ["ok", `Abruf ${ago(s.lastPull)}`];
  return [late < 30 * 60 ? "warn" : "down", `kein Abruf seit ${ago(s.lastPull).slice(4)}`];
}

// counts: stats.sensors [{sensor, n, ips, last}]; selected: Sensor-Name oder null (alle)
export function renderSensorCards(el, counts, selected, onSelect, onOpen) {
  const by = Object.fromEntries((counts || []).map(c => [c.sensor, c]));
  const total = (counts || []).reduce((a, c) => a + c.n, 0);
  const card = (key, color, title, where, c, state) =>
    `<div class="sensor" role="button" tabindex="0" data-sensor="${key}" aria-pressed="${selected === (key || null)}" style="--s:${color}">` +
    `<span class="s-head"><i></i><b>${esc(title)}</b>${state ? `<span class="s-state ${state[0]}">${esc(state[1])}</span>` : ""}</span>` +
    `<span class="s-where">${esc(where)}</span>` +
    `<span class="s-num"><strong>${num(c?.n ?? 0)}</strong> Angriffe${c?.ips != null ? ` · ${num(c.ips)} IPs` : ""}</span>` +
    `<span class="s-last">${c?.last ? `letzter ${ago(c.last)}` : "keine im Zeitfenster"}` +
    (key ? ` · <a href="#" data-open="${key}">Vorgänge →</a>` : "") + "</span></div>";
  const last = Math.max(0, ...(counts || []).map(c => c.last)) || null;
  el.innerHTML = card("", "#a3afc4", "Alle Sensoren", `${sites.length} Standorte`, { n: total, last }, null) +
    sites.map(s => card(s.name, s.color, s.label, s.where || "Außensensor", by[s.name], health(s))).join("");
  // div statt button: die Karte enthält den Link „Vorgänge“, Links in Buttons sind ungültig
  el.querySelectorAll(".sensor").forEach(b => {
    b.onclick = () => onSelect(b.dataset.sensor || null);
    b.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); b.click(); } };
  });
  el.querySelectorAll("[data-open]").forEach(a => {
    a.onclick = e => { e.preventDefault(); e.stopPropagation(); onOpen(a.dataset.open); };
  });
}
