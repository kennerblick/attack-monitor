// KI-Lagebild: Lagebericht (LLM), Trend & Prognose, Kampagnen, passende Meldungen; Sitzungsanalyse fürs IP-Profil. Daten: /api/insights (insights.py).
// LLM-Texte kommen gefiltert vom Server und werden trotzdem nur escaped bzw. als textContent eingesetzt.
import { num, flag, esc } from "./format.js";
import { renderForecast } from "./charts.js";

const $ = id => document.getElementById(id);
export const INTENT = {
  recon: "Recon", "credential-stuffing": "Credentials", "botnet-recruitment": "Botnet", cryptomining: "Cryptomining",
  persistence: "Persistence", exploitation: "Exploit", ransom: "Ransom", other: "Other",
};
const RISK = { low: "low", medium: "medium", high: "high" };

// KI-Analyse der Befehlsfolge einer IP (drawer.js, Daten aus /api/ip → session)
export function sessionBlock(s) {
  if (!s) return "";
  const head = "<b>AI analysis of the session</b>";
  if (!s.analysis) return `<div class="ai-box">${head}<p class="empty">Will be created in one of the next analysis runs.</p></div>`;
  const a = s.analysis;
  return `<div class="ai-box">${head} <span class="intent">${esc(INTENT[a.intent] || a.intent)}</span>` +
    (a.risk ? ` <span class="risk risk-${a.risk}">risk ${RISK[a.risk]}</span>` : "") +
    `<p>${esc(a.summary)}</p><small>${esc(s.model)} · local language model, may be wrong</small></div>`;
}

function ago(ts) {
  const min = Math.round((Date.now() / 1000 - ts) / 60);
  return min < 60 ? `${Math.max(1, min)} min ago` : `${Math.round(min / 60)} h ago`;
}

const hhmm = ts => new Date(ts * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });

function renderReport(report, llm) {
  const el = $("report");
  el.classList.toggle("empty", !report);
  el.textContent = report ? report.text
    : llm ? "The first situation report is being generated …" : "AI situation report is currently unavailable.";
  $("report-meta").textContent = report ? `${ago(report.ts)} · ${report.model}` : "";
}

function renderTrend(trend) {
  if (!trend) return;
  renderForecast($("forecast"), trend);
  const dev = trend.deviation;
  const parts = [
    dev == null ? "No comparison data yet" : `Last 6 h: ${dev > 0 ? "+" : ""}${dev}% ${dev >= 0 ? "above" : "below"} expected`,
    `Forecast next 24 h: ~${num(trend.next24)} (last 24 h: ${num(trend.last24)})`,
  ];
  if (trend.anomalies.length) parts.push(`${trend.anomalies.length} spike${trend.anomalies.length > 1 ? "s" : ""} (red)`);
  $("trend-note").textContent = parts.join(" · ");
}

function title(c) {
  if (c.label) return c.label.name;
  if (c.kind === "wave") return `Wave from ${c.asns[0]?.[1] || c.asns[0]?.[0]}`;
  return c.kind === "commands" ? `Command sequence (${c.size} commands)` : `Password list (${c.size} pairs)`;
}

function campaignItem(c) {
  const badge = c.label ? `<span class="intent">${esc(INTENT[c.label.intent] || c.label.intent)}</span>`
    : c.kind === "wave" ? `<span class="intent wave">${c.factor ? `×${num(c.factor)}` : "wave"}</span>` : "";
  const flags = c.countries.map(([cc]) => flag(cc)).join("");
  const sample = c.sample.length ? `<code>${esc(c.sample.slice(0, 3).join(" ; "))}</code>` : "";
  return `<li class="pick"><div class="ct"><b>${esc(title(c))}</b>${badge}</div>` +
    (c.label?.summary ? `<p>${esc(c.label.summary)}</p>` : "") + sample +
    `<small>${num(c.ips)} IPs · ${num(c.events)} events · ${hhmm(c.first)}–${hhmm(c.last)} ${flags}</small></li>`;
}

function renderCampaigns(list, onPick) {
  const el = $("campaigns");
  if (!list.length) { el.innerHTML = '<li class="empty">No campaigns in the last 24 h.</li>'; return; }
  el.innerHTML = list.map(campaignItem).join("");
  [...el.children].forEach((li, i) => {
    const c = list[i];
    li.onclick = () => onPick(c.drill.kind, c.drill.value, `Campaign: ${esc(title(c))}`, "24h");
  });
}

const day = ts => new Date(ts * 1000).toLocaleDateString("en-GB", { day: "2-digit", month: "2-digit" });

function renderRelated(list) {
  const el = $("related");
  if (!list?.length) { el.innerHTML = '<p class="empty">No reports matching the observed attacks.</p>'; return; }
  el.innerHTML = list.map(r => `<div class="topic"><b>${esc(r.label)}</b><small>${num(r.events)} events · ${num(r.ips)} IPs · 7 days</small>` +
    `<ul>${r.matches.map(m => `<li><a href="${esc(m.url)}" target="_blank" rel="noopener noreferrer nofollow">${esc(m.title)}</a>` +
      `<small>${esc(m.source)} · ${day(m.date)}</small></li>`).join("")}</ul></div>`).join("");
}

export function renderInsights(data, onPick) {
  renderReport(data.report, data.llm);
  renderRelated(data.related);
  renderTrend(data.trend);
  renderCampaigns(data.campaigns, onPick);
}

export const redrawForecast = data => data?.trend && renderForecast($("forecast"), data.trend);
