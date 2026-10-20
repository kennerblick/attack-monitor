// 3D-Globus: Länder als Punktraster (nach Angriffen eingefärbt), Angriffsherde als Säulen,
// Live-Angriffe als Bögen zum Server. Hover zeigt Details, Klick meldet Land/Angriff an main.js.
import { typeInfo, num, flag, esc, time } from "./format.js";
import { ISO_NUMERIC } from "./iso-numeric.js";

const ARC_LIFETIME = 4200;
const RING_LIFETIME = 2600;
const MAX_ARCS = 80;

const BASE_DOT = "rgba(120, 160, 230, 0.45)";

function typeBreakdown(types) {
  const total = Object.values(types).reduce((a, b) => a + b, 0) || 1;
  return Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, n]) => {
    const t = typeInfo(k);
    return `<div class="tt-row"><i style="background:${t.color}"></i>${esc(t.label)}<b>${num(n)}</b>` +
      `<span class="tt-bar"><span style="width:${(n / total) * 100}%;background:${t.color}"></span></span></div>`;
  }).join("");
}

function countryLabel(f, info) {
  const name = info?.country || f.properties.name;
  if (!info) return `<div class="tt"><b>${flag(f.cc)} ${esc(name)}</b><small>keine Angriffe im Zeitfenster</small></div>`;
  return `<div class="tt"><b>${flag(f.cc)} ${esc(name)}</b>` +
    `<small>${num(info.n)} Angriffe · ${num(info.ips)} IPs · zuletzt ${time(info.last)}</small>${typeBreakdown(info.types)}` +
    `<small class="tt-hint">Klick: Details</small></div>`;
}

const pointLabel = p => `<div class="tt"><b>${flag(p.cc)} ${esc(p.city || p.cc || "unbekannt")}</b>` +
  `<small>${num(p.n)} Angriffe · ${num(p.ips)} IPs · zuletzt ${time(p.last)}</small><small class="tt-hint">Klick: Land anzeigen</small></div>`;

function arcLabel(a) {
  const ev = a.ev, t = typeInfo(ev.type);
  return `<div class="tt"><b style="color:${t.color}">${esc(t.label)}</b>` +
    `<small>${flag(ev.cc)} ${esc(ev.city || ev.country || "")} · ${esc(ev.ip)}</small>` +
    `<small>${esc(ev.isp || "")} ${esc(ev.asn || "")}</small><small>${time(ev.ts)} · ${esc(ev.detail)}</small>` +
    `<small class="tt-hint">Klick: Details</small></div>`;
}

export async function createGlobe(el, server, { onCountry, onEvent } = {}) {
  const topo = await fetch("/assets/vendor/countries-110m.json").then(r => r.json());
  const countries = window.topojson.feature(topo, topo.objects.countries).features;
  countries.forEach(f => {
    f.cc = ISO_NUMERIC[Number(f.id)];
    // world-atlas 110m enthält zu einem Punkt kollabierte Teilpolygone (z. B. Nordkorea),
    // an denen H3 scheitert – der Fehler bricht sonst jede Umfärbung aller Länder ab
    if (f.geometry.type === "MultiPolygon") {
      f.geometry.coordinates = f.geometry.coordinates.filter(poly => new Set(poly[0].map(String)).size >= 3);
    }
  });
  let byCountry = {};
  let maxCountry = 1;
  let hovered = null;
  const layers = { shade: true, points: true, arcs: true };
  let spots = [];

  // Färbung nach Angriffen: logarithmisch von Grundblau nach Rot, gehovertes Land hell
  const dotColor = f => {
    if (f === hovered) return "rgba(255, 255, 255, 0.95)";
    const info = layers.shade && byCountry[f.cc];
    if (!info) return BASE_DOT;
    const v = Math.log10(info.n + 1) / Math.log10(maxCountry + 1);
    return `hsla(${Math.round(210 - v * 205)}, 85%, ${55 + v * 10}%, ${0.55 + v * 0.45})`;
  };

  const world = window.Globe({ animateIn: true })(el)
    .backgroundColor("rgba(0,0,0,0)")
    .showAtmosphere(true).atmosphereColor("#3987e5").atmosphereAltitude(0.2)
    .hexPolygonsData(countries).hexPolygonResolution(3).hexPolygonMargin(0.62).hexPolygonUseDots(true)
    .hexPolygonColor(dotColor)
    .hexPolygonLabel(f => countryLabel(f, byCountry[f.cc]))
    .onHexPolygonHover(f => { hovered = f; world.hexPolygonColor(dotColor); el.style.cursor = f ? "pointer" : ""; })
    .onHexPolygonClick(f => f.cc && onCountry?.(f.cc))
    // Säulen: Angriffsherde des Zeitfensters, Höhe logarithmisch nach Anzahl
    // (nicht gemergt, sonst gibt es kein Hover/Klick je Säule)
    .pointRadius(0.32).pointColor(() => "#4fd1ff").pointsTransitionDuration(400)
    .pointAltitude(d => 0.01 + Math.log10(d.n + 1) * 0.06)
    .pointLabel(pointLabel).onPointClick(p => p.cc && onCountry?.(p.cc))
    // Bögen: einzelne Live-Angriffe
    .arcColor("colors").arcStroke(0.7).arcAltitudeAutoScale(0.45)
    .arcLabel(arcLabel).onArcClick(a => onEvent?.(a.ev))
    .arcDashLength(0.45).arcDashGap(1.4).arcDashInitialGap(1).arcDashAnimateTime(1600)
    .arcsTransitionDuration(0)
    // Ringe: Einschlag am Ursprung
    .ringColor(d => t => `${d.color}${Math.round((1 - t) * 255).toString(16).padStart(2, "0")}`)
    .ringMaxRadius(d => d.r).ringPropagationSpeed(2.4).ringRepeatPeriod(900)
    .htmlElementsData([{ lat: server.lat, lng: server.lon }])
    .htmlElement(() => {
      const tag = document.createElement("div");
      tag.style.cssText = "font:700 10px ui-monospace,monospace;letter-spacing:.14em;color:#e7ecf5;" +
        "background:#3987e5cc;padding:3px 7px;border-radius:6px;transform:translate(-50%,-160%);white-space:nowrap";
      tag.textContent = "◉ 3LIS.DE";
      return tag;
    });

  const mat = world.globeMaterial();
  mat.color.set("#0a1633");
  mat.emissive.set("#071030");
  mat.shininess = 0.6;

  const controls = world.controls();
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.35;
  controls.enableZoom = true;
  world.pointOfView({ lat: 28, lng: 12, altitude: 2.3 }, 0);

  const fit = () => world.width(el.clientWidth).height(el.clientHeight);
  new ResizeObserver(fit).observe(el);
  fit();

  const serverRing = { lat: server.lat, lng: server.lon, color: "#4fd1ff", r: 4.5, perm: true };
  let arcs = [];
  let rings = [serverRing];
  let active = null; // Set der sichtbaren Typen, null = alle

  function prune() {
    const now = performance.now();
    arcs = arcs.filter(a => now - a.born < ARC_LIFETIME).slice(-MAX_ARCS);
    rings = rings.filter(r => r.perm || now - r.born < RING_LIFETIME);
    world.arcsData(layers.arcs ? arcs : []).ringsData(rings);
  }
  setInterval(prune, 500);

  let resume = null;
  const pauseRotation = ms => {
    controls.autoRotate = false;
    clearTimeout(resume);
    if (ms) resume = setTimeout(() => { controls.autoRotate = rotating; }, ms);
  };
  let rotating = true;
  // Beim Ziehen/Zoomen nicht sofort weiterdrehen
  controls.addEventListener("start", () => pauseRotation(rotating ? 10000 : 0));

  return {
    setStats(stats) {
      byCountry = stats.byCountry || {};
      maxCountry = Math.max(1, ...Object.values(byCountry).map(c => c.n));
      spots = stats.hotspots.map(s => ({ ...s, lng: s.lon }));
      world.hexPolygonColor(dotColor).pointsData(layers.points ? spots : []);
    },
    setFilter(types) { active = types; },
    toggleLayer(key) {
      layers[key] = !layers[key];
      world.hexPolygonColor(dotColor).pointsData(layers.points ? spots : []);
      prune();
      return layers[key];
    },
    toggleRotation() {
      rotating = !rotating;
      clearTimeout(resume);
      controls.autoRotate = rotating;
      return rotating;
    },
    resetView() {
      world.pointOfView({ lat: server.lat, lng: server.lon, altitude: 2.3 }, 1000);
    },
    addAttack(ev) {
      if (ev.lat == null || (active && !active.has(ev.type))) return;
      const c = typeInfo(ev.type).color;
      const born = performance.now();
      arcs.push({ startLat: ev.lat, startLng: ev.lon, endLat: server.lat, endLng: server.lon, colors: [`${c}00`, c], born, ev });
      rings.push({ lat: ev.lat, lng: ev.lon, color: c, r: 3, born });
      world.arcsData(arcs).ringsData(rings);
    },
    focus(lat, lon) {
      pauseRotation(rotating ? 8000 : 0);
      world.pointOfView({ lat, lng: lon, altitude: 1.6 }, 1200);
    },
    focusCountry(cc) {
      const top = spots.find(s => s.cc === cc); // Säulen sind nach Anzahl sortiert
      const f = countries.find(x => x.cc === cc);
      if (top) this.focus(top.lat, top.lon);
      else if (f) {
        // grobe Mitte: Durchschnitt des äußeren Rings des ersten Teilpolygons
        const ring = f.geometry.type === "Polygon" ? f.geometry.coordinates[0] : f.geometry.coordinates[0][0];
        const avg = i => ring.reduce((a, p) => a + p[i], 0) / ring.length;
        this.focus(avg(1), avg(0));
      }
    },
  };
}
