// Seitliche Schublade: Vorgänge zu einem Top-Listen-Eintrag, Event mit IP-Profil, Länderansicht.
// Jede Ansicht ist ein Eintrag im Verlauf, "Zurück" springt zur vorigen.
import { typeInfo, num, flag, time, dateTime, esc, service, SEVERITY } from "./format.js";
import { feedItem } from "./panels.js";

const $ = id => document.getElementById(id);
const getJson = url => fetch(url, { cache: "no-store" }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
const history = [];
let ctx = { range: "24h", focus: null };

export function initDrawer(options) {
  ctx = { ...ctx, ...options };
  $("drawer-close").onclick = close;
  $("drawer-back").onclick = () => { history.pop(); const prev = history.pop(); prev ? prev() : close(); };
  addEventListener("keydown", e => { if (e.key === "Escape") close(); });
}

export const setRange = range => { ctx.range = range; };

function close() {
  history.length = 0;
  $("drawer").classList.remove("open");
}

function show(view, title, html) {
  history.push(view);
  $("drawer-title").innerHTML = title;
  $("drawer-body").innerHTML = html;
  $("drawer-back").hidden = history.length < 2;
  $("drawer").classList.add("open");
  $("drawer-body").scrollTop = 0;
}

const dl = rows => `<dl>${rows.filter(([, v]) => v != null && v !== "").map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
const chips = (rows, fmt) => rows.length ? rows.map(fmt).join(" · ") : "–";

function bindEvents(events) {
  $("drawer-body").querySelectorAll("li[data-id]").forEach(li => {
    li.onclick = () => openEvent(events.find(e => e.id === Number(li.dataset.id)));
  });
}

const RANGE_LABEL = { "1h": "letzte Stunde", "24h": "letzte 24 Stunden", "7d": "letzte 7 Tage" };

export async function openList(kind, value, label) {
  const view = () => openList(kind, value, label);
  show(view, label, '<p class="empty">Lade Vorgänge …</p>');
  try {
    const { total, events } = await getJson(`/api/events?kind=${kind}&value=${encodeURIComponent(value)}&range=${ctx.range}`);
    if (history.at(-1) !== view) return; // inzwischen andere Ansicht geöffnet
    $("drawer-body").innerHTML = `<p class="sub">${num(total)} Vorgänge · ${RANGE_LABEL[ctx.range]}` +
      `${total > events.length ? ` · neueste ${events.length}` : ""}</p>` +
      `<ul class="feed">${events.map(feedItem).join("") || '<li class="empty">Keine Vorgänge</li>'}</ul>`;
    bindEvents(events);
  } catch {
    $("drawer-body").innerHTML = '<p class="empty">Konnte Vorgänge nicht laden.</p>';
  }
}

export async function openEvent(ev) {
  const view = () => openEvent(ev);
  const t = typeInfo(ev.type);
  if (ev.lat != null) ctx.focus?.(ev.lat, ev.lon);
  show(view, `<span style="color:${t.color}">${esc(t.label)}</span> · ${time(ev.ts)}`, dl([
    ["Zeit", dateTime(ev.ts)], ["Art", `${esc(t.label)} · ${SEVERITY[ev.sev] || esc(ev.sev)}`], ["Quelle", esc(ev.src)],
    ["Port", ev.port ? `${ev.port} ${service(ev.port)}` : null], ["Jail", esc(ev.jail)], ["Detail", esc(ev.detail)],
  ]) + '<h3>Absender</h3><div id="ip-profile"><p class="empty">Lade IP-Profil …</p></div>');
  try {
    const p = await getJson(`/api/ip?id=${ev.id}`);
    if (history.at(-1) === view) renderProfile(p, ev);
  } catch {
    $("ip-profile").innerHTML = '<p class="empty">Kein Profil verfügbar.</p>';
  }
}

const YES_NO = v => (v == null ? "unbekannt" : v ? "ja" : "nein");

function renderProfile(p, ev) {
  const g = p.geo;
  const ban = p.banned.length ? `gesperrt (${p.banned.map(esc).join(", ")})` : "nicht gesperrt";
  const asnLink = g.asn ? `<a href="https://bgp.he.net/${esc(g.asn)}" target="_blank" rel="noopener">${esc(g.asn)} ↗</a>` : null;
  $("ip-profile").innerHTML =
    `<div class="verdict cat-${p.cls.category}"><b>${esc(p.cls.name || p.cls.label)}</b>` +
    `${p.cls.name ? `<small>${esc(p.cls.label)}</small>` : ""}<p>${esc(p.cls.desc)}</p><p class="v">${esc(p.verdict)}</p></div>` +
    dl([
      ["IP", `${esc(p.ip)} <small>(/24 gekürzt)</small>`], ["rDNS", esc(p.host) || "–"],
      ["Ort", g.cc ? `${flag(g.cc)} ${esc(g.city || "")}, ${esc(g.country)}` : "–"],
      ["Provider", esc(g.isp)], ["Organisation", g.org && g.org !== g.isp ? esc(g.org) : null], ["ASN", asnLink],
      ["Rechenzentrum", YES_NO(g.hosting)], ["Proxy/VPN", YES_NO(g.proxy)], ["Mobilfunk", YES_NO(g.mobile)],
      ["Aktivität", `${num(p.n)} Vorgänge an ${p.days} Tag${p.days === 1 ? "" : "en"}`],
      ["Erstmals", dateTime(p.first)], ["Zuletzt", dateTime(p.last)],
      ["Arten", chips(Object.entries(p.types), ([k, n]) => `<span style="color:${typeInfo(k).color}">${esc(typeInfo(k).label)}</span> ${num(n)}`)],
      ["Ports", p.ports.length ? chips(p.ports, ([port, n]) => `${port} <small>${service(port)}</small> ${num(n)}`) : null],
      ["Benutzer", p.users.length ? chips(p.users, ([u, n]) => `${esc(u)} ${num(n)}`) : null],
      ["Passwörter", p.passwords.length ? chips(p.passwords, ([pw, n]) => `${esc(pw)} ${num(n)}`) : null],
      ["Befehle", p.commands.length ? chips(p.commands, ([c, n]) => `${esc(c)} ${num(n)}`) : null],
      ["Pfade", p.paths.length ? chips(p.paths, ([u, n]) => `${esc(u)} ${num(n)}`) : null],
      ["Netz /24", `${num(p.subnetIps)} angreifende IP${p.subnetIps === 1 ? "" : "s"} aus ${esc(p.ip.replace(/\.x$/, ".0/24"))}`],
      ["Sperre", `fail2ban: ${ban} · Sperrliste: ${p.denied ? "ja" : "nein"}`],
    ]) + `<button class="link-btn" id="ip-all">Alle ${num(p.n)} Vorgänge dieser IP →</button>`;
  $("ip-all").onclick = () => openList("ip", ev.id, `Vorgänge von ${esc(p.ip)}`);
}

export function openCountry(cc, info, spots) {
  const types = Object.entries(info.types).sort((a, b) => b[1] - a[1]);
  show(() => openCountry(cc, info, spots), `${flag(cc)} ${esc(info.country)}`, dl([
    ["Angriffe", num(info.n)], ["IPs", num(info.ips)], ["Zuletzt", dateTime(info.last)],
    ["Orte", chips(spots.slice(0, 6), s => `${esc(s.city || "?")} ${num(s.n)}`)],
    ["Arten", chips(types, ([k, n]) => `<span style="color:${typeInfo(k).color}">${esc(typeInfo(k).label)}</span> ${num(n)}`)],
  ]) + '<h3>Vorgänge</h3><div id="country-list"><p class="empty">Lade …</p></div>');
  const view = history.at(-1);
  getJson(`/api/events?kind=cc&value=${encodeURIComponent(cc)}&range=${ctx.range}`).then(({ events }) => {
    if (history.at(-1) !== view) return;
    $("country-list").innerHTML = `<ul class="feed">${events.map(feedItem).join("")}</ul>`;
    bindEvents(events);
  }).catch(() => { $("country-list").innerHTML = '<p class="empty">Konnte Vorgänge nicht laden.</p>'; });
}
