// Seitliche Schublade: Vorgänge zu einem Top-Listen-Eintrag, Event mit IP-Profil, Länderansicht.
// Jede Ansicht ist ein Eintrag im Verlauf, "Zurück" springt zur vorigen.
import { typeInfo, num, flag, time, dateTime, esc, service, SEVERITY } from "./format.js";
import { feedItem } from "./panels.js";
import { sensorBadge } from "./sensors.js";
import { sessionBlock } from "./insights.js";

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

const RANGE_LABEL = { "1h": "last hour", "24h": "last 24 hours", "7d": "last 7 days" };

export async function openList(kind, value, label, range = ctx.range) {
  const view = () => openList(kind, value, label, range);
  show(view, label, '<p class="empty">Loading events …</p>');
  try {
    const { total, events } = await getJson(`/api/events?kind=${kind}&value=${encodeURIComponent(value)}&range=${range}`);
    if (history.at(-1) !== view) return; // inzwischen andere Ansicht geöffnet
    $("drawer-body").innerHTML = `<p class="sub">${num(total)} events · ${RANGE_LABEL[range]}` +
      `${total > events.length ? ` · neueste ${events.length}` : ""}</p>` +
      `<ul class="feed">${events.map(feedItem).join("") || '<li class="empty">No events</li>'}</ul>`;
    bindEvents(events);
  } catch {
    $("drawer-body").innerHTML = '<p class="empty">Could not load events.</p>';
  }
}

// Nur der Hash geht an VirusTotal; die Datei selbst liegt nie öffentlich (samples.py)
function sampleLink(detail) {
  const hash = /^Sample “([0-9a-f]{64})”/.exec(detail || "")?.[1];
  return hash && `<a href="https://www.virustotal.com/gui/file/${hash}" target="_blank" rel="noopener noreferrer">VirusTotal ↗</a>`;
}

export async function openEvent(ev) {
  const view = () => openEvent(ev);
  const t = typeInfo(ev.type);
  if (ev.lat != null) ctx.focus?.(ev.lat, ev.lon);
  show(view, `<span style="color:${t.color}">${esc(t.label)}</span> · ${time(ev.ts)}`, dl([
    ["Time", dateTime(ev.ts)], ["Type", `${esc(t.label)} · ${SEVERITY[ev.sev] || esc(ev.sev)}`], ["Source", esc(ev.src)], ["Sensor", sensorBadge(ev.sensor)],
    ["Port", ev.port ? `${esc(ev.port)} ${service(ev.port)}` : null], ["Jail", esc(ev.jail)], ["Detail", esc(ev.detail)],
    ["Analysis", sampleLink(ev.detail)],
  ]) + '<h3>Sender</h3><div id="ip-profile"><p class="empty">Loading IP profile …</p></div>');
  try {
    const p = await getJson(`/api/ip?id=${ev.id}`);
    if (history.at(-1) === view) renderProfile(p, ev);
  } catch {
    $("ip-profile").innerHTML = '<p class="empty">No profile available.</p>';
  }
}

const YES_NO = v => (v == null ? "unknown" : v ? "yes" : "no");

function renderProfile(p, ev) {
  const g = p.geo;
  const ban = p.banned.length ? `banned (${p.banned.map(esc).join(", ")})` : "not banned";
  const asnLink = g.asn ? `<a href="https://bgp.he.net/${esc(g.asn)}" target="_blank" rel="noopener">${esc(g.asn)} ↗</a>` : null;
  $("ip-profile").innerHTML =
    `<div class="verdict cat-${p.cls.category}"><b>${esc(p.cls.name || p.cls.label)}</b>` +
    `${p.cls.name ? `<small>${esc(p.cls.label)}</small>` : ""}<p>${esc(p.cls.desc)}</p><p class="v">${esc(p.verdict)}</p></div>` +
    sessionBlock(p.session) +
    dl([
      ["IP", `${esc(p.ip)} <small>(truncated to /24)</small>`], ["rDNS", esc(p.host) || "–"],
      ["Location", g.cc ? `${flag(g.cc)} ${esc(g.city || "")}, ${esc(g.country)}` : "–"],
      ["Provider", esc(g.isp)], ["Organization", g.org && g.org !== g.isp ? esc(g.org) : null], ["ASN", asnLink],
      ["Data center", YES_NO(g.hosting)], ["Proxy/VPN", YES_NO(g.proxy)], ["Mobile", YES_NO(g.mobile)],
      ["Activity", `${num(p.n)} events on ${p.days} day${p.days === 1 ? "" : "s"}`],
      ["First seen", dateTime(p.first)], ["Last seen", dateTime(p.last)],
      ["Types", chips(Object.entries(p.types), ([k, n]) => `<span style="color:${typeInfo(k).color}">${esc(typeInfo(k).label)}</span> ${num(n)}`)],
      ["Ports", p.ports.length ? chips(p.ports, ([port, n]) => `${esc(port)} <small>${service(port)}</small> ${num(n)}`) : null],
      ["Users", p.users.length ? chips(p.users, ([u, n]) => `${esc(u)} ${num(n)}`) : null],
      ["Passwords", p.passwords.length ? chips(p.passwords, ([pw, n]) => `${esc(pw)} ${num(n)}`) : null],
      ["Commands", p.commands.length ? chips(p.commands, ([c, n]) => `${esc(c)} ${num(n)}`) : null],
      ["Paths", p.paths.length ? chips(p.paths, ([u, n]) => `${esc(u)} ${num(n)}`) : null],
      ["Network /24", `${num(p.subnetIps)} attacking IP${p.subnetIps === 1 ? "" : "s"} from ${esc(p.ip.replace(/\.x$/, ".0/24"))}`],
      ["Block", `fail2ban: ${ban} · blocklist: ${p.denied ? "yes" : "no"}`],
    ]) + `<button class="link-btn" id="ip-all">All ${num(p.n)} events of this IP →</button>`;
  $("ip-all").onclick = () => openList("ip", ev.id, `Events from ${esc(p.ip)}`);
}

export function openCountry(cc, info, spots) {
  const types = Object.entries(info.types).sort((a, b) => b[1] - a[1]);
  show(() => openCountry(cc, info, spots), `${flag(cc)} ${esc(info.country)}`, dl([
    ["Attacks", num(info.n)], ["IPs", num(info.ips)], ["Last seen", dateTime(info.last)],
    ["Orte", chips(spots.slice(0, 6), s => `${esc(s.city || "?")} ${num(s.n)}`)],
    ["Arten", chips(types, ([k, n]) => `<span style="color:${typeInfo(k).color}">${esc(typeInfo(k).label)}</span> ${num(n)}`)],
  ]) + '<h3>Events</h3><div id="country-list"><p class="empty">Loading …</p></div>');
  const view = history.at(-1);
  getJson(`/api/events?kind=cc&value=${encodeURIComponent(cc)}&range=${ctx.range}`).then(({ events }) => {
    if (history.at(-1) !== view) return;
    $("country-list").innerHTML = `<ul class="feed">${events.map(feedItem).join("")}</ul>`;
    bindEvents(events);
  }).catch(() => { $("country-list").innerHTML = '<p class="empty">Could not load events.</p>'; });
}
