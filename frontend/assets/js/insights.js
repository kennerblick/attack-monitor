// KI-Lagebild: Lagebericht (LLM, englisch), Trend & Prognose, Kampagnen. Daten: /api/insights (insights.py).
// LLM-Texte kommen gefiltert vom Server und werden trotzdem nur escaped bzw. als textContent eingesetzt.
import { num, flag, esc } from "./format.js";
import { renderForecast } from "./charts.js";

const $ = id => document.getElementById(id);
const INTENT = {
  recon: "Aufklärung", "credential-stuffing": "Zugangsdaten", "botnet-recruitment": "Botnetz", cryptomining: "Krypto-Mining",
  persistence: "Einnisten", exploitation: "Exploit", other: "Sonstiges",
};

function ago(ts) {
  const min = Math.round((Date.now() / 1000 - ts) / 60);
  return min < 60 ? `vor ${Math.max(1, min)} Min.` : `vor ${Math.round(min / 60)} Std.`;
}

const hhmm = ts => new Date(ts * 1000).toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });

function renderReport(report, llm) {
  const el = $("report");
  el.classList.toggle("empty", !report);
  el.textContent = report ? report.text
    : llm ? "Der erste Lagebericht wird gerade erstellt …" : "KI-Lagebericht ist derzeit nicht verfügbar.";
  $("report-meta").textContent = report ? `${ago(report.ts)} · ${report.model}` : "";
}

function renderTrend(trend) {
  if (!trend) return;
  renderForecast($("forecast"), trend);
  const dev = trend.deviation;
  const parts = [
    dev == null ? "Noch keine Vergleichsdaten" : `Letzte 6 Std.: ${dev > 0 ? "+" : ""}${dev} % ${dev >= 0 ? "über" : "unter"} Erwartung`,
    `Prognose nächste 24 Std.: ~${num(trend.next24)} (zuletzt ${num(trend.last24)})`,
  ];
  if (trend.anomalies.length) parts.push(`${trend.anomalies.length} Spitze${trend.anomalies.length > 1 ? "n" : ""} (rot)`);
  $("trend-note").textContent = parts.join(" · ");
}

function title(c) {
  if (c.label) return c.label.name;
  if (c.kind === "wave") return `Welle aus ${c.asns[0]?.[1] || c.asns[0]?.[0]}`;
  return c.kind === "commands" ? `Befehlsfolge (${c.size} Befehle)` : `Passwortliste (${c.size} Paare)`;
}

function campaignItem(c) {
  const badge = c.label ? `<span class="intent">${esc(INTENT[c.label.intent] || c.label.intent)}</span>`
    : c.kind === "wave" ? `<span class="intent wave">${c.factor ? `×${num(c.factor)}` : "Welle"}</span>` : "";
  const flags = c.countries.map(([cc]) => flag(cc)).join("");
  const sample = c.sample.length ? `<code>${esc(c.sample.slice(0, 3).join(" ; "))}</code>` : "";
  return `<li class="pick"><div class="ct"><b>${esc(title(c))}</b>${badge}</div>` +
    (c.label?.summary ? `<p>${esc(c.label.summary)}</p>` : "") + sample +
    `<small>${num(c.ips)} IPs · ${num(c.events)} Vorgänge · ${hhmm(c.first)}–${hhmm(c.last)} ${flags}</small></li>`;
}

function renderCampaigns(list, onPick) {
  const el = $("campaigns");
  if (!list.length) { el.innerHTML = '<li class="empty">Keine Kampagnen in den letzten 24 Std.</li>'; return; }
  el.innerHTML = list.map(campaignItem).join("");
  [...el.children].forEach((li, i) => {
    const c = list[i];
    li.onclick = () => onPick(c.drill.kind, c.drill.value, `Kampagne: ${esc(title(c))}`, "24h");
  });
}

export function renderInsights(data, onPick) {
  renderReport(data.report, data.llm);
  renderTrend(data.trend);
  renderCampaigns(data.campaigns, onPick);
}

export const redrawForecast = data => data?.trend && renderForecast($("forecast"), data.trend);
