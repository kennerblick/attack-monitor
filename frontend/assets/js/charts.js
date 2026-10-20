// SVG-Diagramme: gestapelte Zeitleiste nach Angriffsart und Wochentag×Stunde-Heatmap, beide mit Tooltip.
import { TYPES, num } from "./format.js";

const NS = "http://www.w3.org/2000/svg";
const tip = document.getElementById("tip");
// Sequenzielle Rampe (ein Farbton, hell = viel) für die Heatmap
const RAMP = ["#14223f", "#173564", "#1d4f95", "#2a6fc9", "#3f8fe8", "#7db6f2", "#c4e0fb"];

function node(tag, attrs, parent) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  parent?.appendChild(el);
  return el;
}

function showTip(evt, html) {
  tip.innerHTML = html;
  tip.style.display = "block";
  const x = Math.min(evt.clientX + 14, innerWidth - tip.offsetWidth - 8);
  tip.style.left = `${x}px`;
  tip.style.top = `${evt.clientY + 14}px`;
}
const hideTip = () => { tip.style.display = "none"; };

function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 2.5, 5, 10].map(m => m * p).find(m => m >= v);
}

function bucketLabel(t, bucket) {
  const d = new Date(t * 1000);
  return bucket >= 3 * 3600
    ? d.toLocaleString("de-DE", { weekday: "short", hour: "2-digit", minute: "2-digit" })
    : d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
}

export function renderTimeline(svg, timeline, active) {
  const W = svg.clientWidth || 800, H = svg.clientHeight || 220, L = 44, B = 24, T = 8;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.innerHTML = "";
  const { buckets, bucket } = timeline;
  const types = TYPES.filter(t => !active || active.has(t.key));
  const totals = buckets.map(b => types.reduce((s, t) => s + (b.counts[t.key] || 0), 0));
  const max = niceMax(Math.max(1, ...totals));
  const y = v => H - B - (v / max) * (H - B - T);
  const step = (W - L) / buckets.length;

  for (let i = 0; i <= 4; i++) {
    const v = (max / 4) * i;
    node("line", { x1: L, x2: W, y1: y(v), y2: y(v), stroke: "#1e2a44", "stroke-width": 1 }, svg);
    node("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end", fill: "#6b7894", "font-size": 10, "font-family": "ui-monospace" }, svg)
      .textContent = num(Math.round(v));
  }
  const every = Math.ceil(buckets.length / 8);
  buckets.forEach((b, i) => {
    const x = L + i * step;
    let acc = 0;
    types.forEach(t => {
      const n = b.counts[t.key] || 0;
      if (!n) return;
      const y0 = y(acc), y1 = y(acc + n);
      node("rect", { x: x + 1, y: y1, width: Math.max(1, step - 2), height: Math.max(0.5, y0 - y1 - 1), fill: t.color, rx: 1.5 }, svg);
      acc += n;
    });
    if (i % every === 0) {
      node("text", { x: x + step / 2, y: H - 6, "text-anchor": "middle", fill: "#6b7894", "font-size": 10, "font-family": "ui-monospace" }, svg)
        .textContent = bucketLabel(b.t, bucket);
    }
    const hit = node("rect", { x, y: T, width: step, height: H - B - T, fill: "transparent" }, svg);
    hit.addEventListener("mousemove", e => showTip(e,
      `<b>${bucketLabel(b.t, bucket)} · ${num(totals[i])}</b>` +
      types.filter(t => b.counts[t.key]).map(t => `<div><span><i style="background:${t.color}"></i>${t.label}</span><span>${num(b.counts[t.key])}</span></div>`).join("")));
    hit.addEventListener("mouseleave", hideTip);
  });
}

const DAYS = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"];

export function renderHeatmap(svg, grid) {
  const W = svg.clientWidth || 400, L = 26, B = 18;
  const cell = (W - L) / 24;
  const H = cell * 7 + B;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.style.height = `${H}px`;
  svg.innerHTML = "";
  const max = Math.max(1, ...grid.flat());
  grid.forEach((row, d) => {
    node("text", { x: 0, y: d * cell + cell / 2 + 4, fill: "#6b7894", "font-size": 10, "font-family": "ui-monospace" }, svg).textContent = DAYS[d];
    row.forEach((n, h) => {
      const level = n ? Math.min(RAMP.length - 1, 1 + Math.floor((n / max) ** 0.75 * (RAMP.length - 1))) : 0;
      const r = node("rect", { x: L + h * cell + 1, y: d * cell + 1, width: cell - 2, height: cell - 2, rx: 3, fill: RAMP[level] }, svg);
      r.addEventListener("mousemove", e => showTip(e, `<b>${DAYS[d]}, ${String(h).padStart(2, "0")}:00–${String(h).padStart(2, "0")}:59</b><div><span>Angriffe</span><span>${num(n)}</span></div>`));
      r.addEventListener("mouseleave", hideTip);
    });
  });
  [0, 6, 12, 18, 23].forEach(h => {
    node("text", { x: L + h * cell + cell / 2, y: H - 4, "text-anchor": "middle", fill: "#6b7894", "font-size": 10, "font-family": "ui-monospace" }, svg)
      .textContent = `${h}h`;
  });
}
