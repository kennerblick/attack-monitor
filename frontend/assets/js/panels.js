// Kennzahlen, Top-Listen, Live-Feed und Toast (Detailansichten: drawer.js).
import { TYPES, typeInfo, num, flag, time, esc, service } from "./format.js";

const $ = id => document.getElementById(id);

function bars(el, rows, render, onPick) {
  if (!rows.length) { el.innerHTML = '<li class="empty">Keine Daten im Zeitfenster</li>'; return; }
  const max = Math.max(...rows.map(r => r.n));
  el.innerHTML = rows.map(r => {
    const { icon, name, color } = render(r);
    return `<li title="${esc(name.replace(/<[^>]+>/g, ""))}: ${num(r.n)}">${icon}<span class="name">${name}</span>` +
      `<span class="val">${num(r.n)}</span><span class="track"><i style="width:${(r.n / max) * 100}%;` +
      `${color ? `background:${color}` : ""}"></i></span></li>`;
  }).join("");
  if (onPick) [...el.children].forEach((li, i) => { li.classList.add("pick"); li.onclick = () => onPick(rows[i]); });
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

export function renderTypes(stats, active, onToggle, onPick) {
  const counts = Object.fromEntries(stats.byType.map(t => [t.type, t.n]));
  const rows = TYPES.map(t => ({ ...t, n: counts[t.key] || 0 }));
  const el = $("types");
  bars(el, rows, r => ({ icon: `<span class="dot" style="background:${r.color}"></span>`, name: r.label, color: r.color }),
    r => onPick("type", r.key, r.label));
  [...el.children].forEach((li, i) => { li.style.opacity = !active || active.has(rows[i].key) ? 1 : 0.35; });
  $("legend").innerHTML = TYPES.map(t =>
    `<button class="chip" data-type="${t.key}" aria-pressed="${!active || active.has(t.key)}"><i style="background:${t.color}"></i>${t.label}</button>`).join("");
  $("legend").querySelectorAll(".chip").forEach(b => { b.onclick = () => onToggle(b.dataset.type); });
}

// onPick(kind, value, title): öffnet die Vorgänge zu einem Eintrag (kind = Filter in /api/events)
export function renderLists(stats, onCountry, onPick) {
  bars($("countries"), stats.countriesTop.slice(0, 8), r => ({ icon: `<span class="flag">${flag(r.cc)}</span>`, name: esc(r.country) }),
    r => onCountry(r.cc));
  bars($("asns"), stats.asnTop.slice(0, 8), r => ({ icon: '<span class="flag">🛰️</span>', name: `${esc(r.isp)}<small>${esc(r.asn)}</small>` }),
    r => onPick("asn", r.asn, `${esc(r.isp)} · ${esc(r.asn)}`));
  bars($("ports"), stats.portsTop, r => ({ icon: '<span class="flag">🎯</span>', name: `${r.port}<small>${service(r.port)}</small>`, color: "#3987e5" }),
    r => onPick("port", r.port, `Port ${r.port} ${service(r.port)}`));
  bars($("users"), stats.usersTop, r => ({
    icon: '<span class="flag">👤</span>', name: `${esc(r.user)}<small>${r.type === "MySQL-Probe" ? "MySQL" : "SSH"}</small>`,
    color: typeInfo(r.type).color,
  }), r => onPick("user", r.user, `Login als „${esc(r.user)}“ (SSH und MySQL)`));
  const rest = stats.usersAll && stats.usersAll.names - stats.usersTop.length;
  if (rest > 0) {
    const shown = stats.usersTop.reduce((sum, r) => sum + r.n, 0);
    $("users").insertAdjacentHTML("beforeend", `<li class="pick more">+ ${num(rest)} weitere Namen · ` +
      `${num(stats.usersAll.n - shown)} Versuche <span class="val">alle ${num(stats.usersAll.n)} →</span></li>`);
    $("users").lastElementChild.onclick = () => onPick("login", "Login-Versuch", "Alle Login-Versuche (SSH und MySQL)");
  }
  bars($("paths"), stats.pathsTop, r => ({ icon: '<span class="flag">🔎</span>', name: esc(r.path), color: "#d95926" }),
    r => onPick("path", r.path, `Pfad ${esc(r.path)}`));
  bars($("jails"), stats.jailsTop, r => ({ icon: '<span class="flag">⛓️</span>', name: esc(r.jail), color: "#c98500" }),
    r => onPick("jail", r.jail, `Jail ${esc(r.jail)}`));
}

export function feedItem(ev) {
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

export function toast(ev) {
  const el = $("toast");
  const t = typeInfo(ev.type);
  el.innerHTML = `<b style="color:${t.color}">${t.label}</b>${ev.cc ? flag(ev.cc) + " " + esc(ev.city || ev.country) : ""} · ${esc(ev.isp || ev.ip)}`;
  el.style.opacity = 1;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.style.opacity = 0; }, 3500);
}
