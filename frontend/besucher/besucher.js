// Besucherstatistik: lädt /api/visits (Tageswerte) und rechnet Kennzahlen und Trend im Browser.
import { num, esc } from "/assets/js/format.js";

const $ = id => document.getElementById(id);
const sum = (rows, key) => rows.reduce((s, r) => s + r[key], 0);
const DAY = new Intl.DateTimeFormat("de-DE", { day: "2-digit", month: "2-digit" });
const MONTH = new Intl.DateTimeFormat("de-DE", { month: "long", year: "numeric" });

function trend(now, before) {
  if (!before) return now ? '<span class="up">neu</span>' : "–";
  const pct = Math.round((now / before - 1) * 100);
  return `<span class="${pct >= 0 ? "up" : "down"}">${pct >= 0 ? "▲" : "▼"} ${Math.abs(pct)} %</span>`;
}

function renderKpis(daily) {
  const last = n => daily.slice(-n), prev = n => daily.slice(-2 * n, -n);
  const kpi = (value, label) => `<div class="kpi"><b>${value}</b><span>${label}</span></div>`;
  $("kpis").innerHTML = [
    kpi(num(daily.at(-1).visitors), "Besucher heute"),
    kpi(num(sum(last(7), "visitors")), "Besucher 7 Tage"),
    kpi(num(sum(last(30), "visitors")), "Besucher 30 Tage"),
    kpi(num(sum(daily, "visitors")), `Besucher gesamt · ${num(sum(daily, "views"))} Aufrufe`),
    kpi(trend(sum(last(7), "visitors"), sum(prev(7), "visitors")), "Trend 7 Tage ggü. Vorwoche"),
    kpi(trend(sum(last(30), "visitors"), sum(prev(30), "visitors")), "Trend 30 Tage ggü. Vormonat"),
  ].join("");
}

function renderChart(svg, daily) {
  const days = daily.slice(-90);
  const w = svg.clientWidth || 800, h = 220, pad = 24, bw = (w - pad) / days.length;
  const max = Math.max(1, ...days.map(d => d.visitors));
  const y = v => h - pad - (v / max) * (h - 2 * pad);
  // gleitender 7-Tage-Schnitt über die volle Reihe, damit der Anfang des Fensters nicht abfällt
  const offset = daily.length - days.length;
  const avg = days.map((_, i) => sum(daily.slice(Math.max(0, offset + i - 6), offset + i + 1), "visitors") /
    Math.min(7, offset + i + 1));
  const bars = days.map((d, i) => `<rect class="bar" x="${pad + i * bw + 1}" y="${y(d.visitors)}" ` +
    `width="${Math.max(1, bw - 2)}" height="${h - pad - y(d.visitors)}"><title>${DAY.format(new Date(d.day))}: ` +
    `${d.visitors} Besucher, ${d.views} Aufrufe</title></rect>`).join("");
  const line = avg.map((v, i) => `${pad + i * bw + bw / 2},${y(v)}`).join(" ");
  const step = Math.ceil(days.length / 8);
  const labels = days.map((d, i) => i % step ? "" :
    `<text x="${pad + i * bw}" y="${h - 6}">${DAY.format(new Date(d.day))}</text>`).join("");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.innerHTML = `<line class="axis" x1="${pad}" x2="${w}" y1="${h - pad}" y2="${h - pad}"/>` +
    `<text x="0" y="${pad}">${max}</text><text x="0" y="${h - pad}">0</text>` +
    bars + `<polyline class="avg" points="${line}"/>` + labels;
}

const table = (el, head, rows) => {
  el.innerHTML = `<tr>${head.map(c => `<th>${c}</th>`).join("")}</tr>` +
    (rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join("")}</tr>`).join("") ||
     `<tr><td colspan="${head.length}">Noch keine Daten</td></tr>`);
};

async function load() {
  const r = await fetch("/api/visits", { cache: "no-store" });
  if (!r.ok) throw new Error(r.status);
  const s = await r.json();
  addEventListener("resize", () => renderChart($("chart"), s.daily));
  renderKpis(s.daily);
  renderChart($("chart"), s.daily);
  table($("monthly"), ["Monat", "Besucher", "Aufrufe"],
    s.monthly.map(m => [MONTH.format(new Date(m.period + "-01")), num(m.visitors), num(m.views)]));
  table($("yearly"), ["Jahr", "Besucher", "Aufrufe"], s.yearly.map(m => [m.period, num(m.visitors), num(m.views)]));
  table($("pages"), ["Seite", "Aufrufe"], s.pages.map(([p, n]) => [`<a href="${esc(p)}">${esc(p)}</a>`, num(n)]));
  table($("referrers"), ["Quelle", "Aufrufe"], s.referrers.map(([h, n]) => [esc(h), num(n)]));
  $("note").textContent = `Daten seit ${new Date(s.since).toLocaleDateString("de-DE")}. Gezählt werden nur Browser, ` +
    "die auch Ressourcen der Seite nachladen; Bots, Angreifer-IPs und Monitoring fallen heraus. Besucher = " +
    "eindeutig pro Tag (anonymer Tages-Hash, keine Cookies); Monats- und Jahreswerte sind die Summe der Tage.";
}

load().catch(() => { $("note").textContent = "Statistik konnte nicht geladen werden."; });
