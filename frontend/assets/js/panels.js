// Kennzahlen, Top-Listen, Live-Feed und Detailansicht.
import { TYPES, typeInfo, num, flag, time, dateTime, esc, service, SEVERITY } from "./format.js";

const $ = id => document.getElementById(id);

function bars(el, rows, render) {
  if (!rows.length) { el.innerHTML = '<li class="empty">Keine Daten im Zeitfenster</li>'; return; }
  const max = Math.max(...rows.map(r => r.n));
  el.innerHTML = rows.map(r => {
    const { icon, name, color } = render(r);
    return `<li title="${esc(name.replace(/<[^>]+>/g, ""))}: ${num(r.n)}">${icon}<span class="name">${name}</span>` +
      `<span class="val">${num(r.n)}</span><span class="track"><i style="width:${(r.n / max) * 100}%;` +
      `${color ? `background:${color}` : ""}"></i></span></li>`;
  }).join("");
}

export function renderKpis(stats, status) {
  if (stats) {
    $("k-total").textContent = num(stats.total);
    $("k-rate").textContent = stats.perMinute.toLocaleString("de-DE", { maximumFractionDigits: 1 });
    $("k-ips").textContent = num(stats.uniqueIps);
    $("k-countries").textContent = num(stats.countries);
    $("k-total-sub").textContent = { "1h": "letzte Stunde", "24h": "letzte 24 Stunden", "7d": "letzte 7 Tage" }[stats.range];
  }
  if (status) {
    $("k-bans").textContent = num(status.bansTotal);
    const top = Object.entries(status.bans).filter(([, n]) => n).map(([j, n]) => `${j} ${n}`).join(" · ");
    $("k-bans-sub").textContent = top || "fail2ban";
    $("k-block").textContent = num(status.blocklist);
    $("server-loc").textContent = `Ziel: ${status.server.name}`;
  }
}

export function renderTypes(stats, active, onToggle) {
  const counts = Object.fromEntries(stats.byType.map(t => [t.type, t.n]));
  const rows = TYPES.map(t => ({ ...t, n: counts[t.key] || 0 }));
  const el = $("types");
  bars(el, rows, r => ({ icon: `<span class="dot" style="background:${r.color}"></span>`, name: r.label, color: r.color }));
  [...el.children].forEach((li, i) => {
    li.style.cursor = "pointer";
    li.style.opacity = !active || active.has(rows[i].key) ? 1 : 0.35;
    li.onclick = () => onToggle(rows[i].key);
  });
  $("legend").innerHTML = TYPES.map(t =>
    `<button class="chip" data-type="${t.key}" aria-pressed="${!active || active.has(t.key)}"><i style="background:${t.color}"></i>${t.label}</button>`).join("");
  $("legend").querySelectorAll(".chip").forEach(b => { b.onclick = () => onToggle(b.dataset.type); });
}

export function renderLists(stats) {
  bars($("countries"), stats.countriesTop.slice(0, 8), r => ({ icon: `<span class="flag">${flag(r.cc)}</span>`, name: esc(r.country) }));
  bars($("asns"), stats.asnTop.slice(0, 8), r => ({ icon: '<span class="flag">🛰️</span>', name: `${esc(r.isp)}<small>${esc(r.asn)}</small>` }));
  bars($("ports"), stats.portsTop, r => ({ icon: '<span class="flag">🎯</span>', name: `${r.port}<small>${service(r.port)}</small>`, color: "#3987e5" }));
  bars($("users"), stats.usersTop, r => ({ icon: '<span class="flag">👤</span>', name: esc(r.user), color: "#199e70" }));
  bars($("paths"), stats.pathsTop, r => ({ icon: '<span class="flag">🔎</span>', name: esc(r.path), color: "#d95926" }));
  bars($("jails"), stats.jailsTop, r => ({ icon: '<span class="flag">⛓️</span>', name: esc(r.jail), color: "#c98500" }));
}

function feedItem(ev) {
  const t = typeInfo(ev.type);
  const where = ev.cc ? `${flag(ev.cc)} ${esc(ev.country)}` : "⏳ lokalisiere …";
  return `<li data-id="${ev.id}" style="--c:${t.color}"><span class="t">${time(ev.ts)}</span>` +
    `<span class="ty" style="color:${t.color}">${t.label}</span><span class="where">${where}</span>` +
    `<span class="d">${esc(ev.ip)} · ${esc(ev.detail)}</span></li>`;
}

export function renderFeed(events, newIds, onSelect) {
  const el = $("feed");
  if (!events.length) { el.innerHTML = '<li class="empty">Keine Angriffe für diesen Filter</li>'; return; }
  el.innerHTML = events.map(feedItem).join("");
  el.querySelectorAll("li[data-id]").forEach(li => {
    const id = Number(li.dataset.id);
    if (newIds.has(id)) li.classList.add("new");
    li.onclick = () => onSelect(events.find(e => e.id === id), li);
  });
  $("feed-count").textContent = `${events.length} neueste`;
}

export function renderDetail(ev) {
  const t = typeInfo(ev.type);
  const rows = [
    ["Zeit", dateTime(ev.ts)], ["Art", `${t.label} · ${SEVERITY[ev.sev] || ev.sev}`], ["Quelle", ev.src],
    ["IP", ev.ip], ["Land", ev.cc ? `${flag(ev.cc)} ${ev.country}` : "–"], ["Stadt", ev.city || "–"],
    ["Provider", ev.isp || "–"], ["ASN", ev.asn || "–"],
    ["Port", ev.port ? `${ev.port} ${service(ev.port)}` : "–"], ["Jail", ev.jail || "–"], ["Detail", ev.detail],
  ];
  const el = $("detail");
  el.innerHTML = `<dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;
  el.classList.add("open");
}

export function toast(ev) {
  const el = $("toast");
  const t = typeInfo(ev.type);
  el.innerHTML = `<b style="color:${t.color}">${t.label}</b>${ev.cc ? flag(ev.cc) + " " + esc(ev.city || ev.country) : ""} · ${esc(ev.isp || ev.ip)}`;
  el.style.opacity = 1;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.style.opacity = 0; }, 3500);
}
