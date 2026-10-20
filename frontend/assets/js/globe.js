// 3D-Globus: Länder als Punktraster, Angriffsherde als Säulen, Live-Angriffe als Bögen zum Server.
import { typeInfo } from "./format.js";

const ARC_LIFETIME = 4200;
const RING_LIFETIME = 2600;
const MAX_ARCS = 80;

export async function createGlobe(el, server) {
  const topo = await fetch("/assets/vendor/countries-110m.json").then(r => r.json());
  const countries = window.topojson.feature(topo, topo.objects.countries).features;

  const world = window.Globe({ animateIn: true })(el)
    .backgroundColor("rgba(0,0,0,0)")
    .showAtmosphere(true).atmosphereColor("#3987e5").atmosphereAltitude(0.2)
    .hexPolygonsData(countries).hexPolygonResolution(3).hexPolygonMargin(0.62).hexPolygonUseDots(true)
    .hexPolygonColor(() => "rgba(120, 160, 230, 0.55)")
    // Säulen: Angriffsherde des Zeitfensters, Höhe logarithmisch nach Anzahl
    .pointsMerge(true).pointRadius(0.32).pointColor(() => "#4fd1ff")
    .pointAltitude(d => 0.01 + Math.log10(d.n + 1) * 0.06)
    // Bögen: einzelne Live-Angriffe
    .arcColor("colors").arcStroke(0.55).arcAltitudeAutoScale(0.45)
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
    world.arcsData(arcs).ringsData(rings);
  }
  setInterval(prune, 500);

  return {
    setHotspots(spots) {
      world.pointsData(spots.map(s => ({ lat: s.lat, lng: s.lon, n: s.n })));
    },
    setFilter(types) { active = types; },
    addAttack(ev) {
      if (ev.lat == null || (active && !active.has(ev.type))) return;
      const c = typeInfo(ev.type).color;
      const born = performance.now();
      arcs.push({ startLat: ev.lat, startLng: ev.lon, endLat: server.lat, endLng: server.lon, colors: [`${c}00`, c], born });
      rings.push({ lat: ev.lat, lng: ev.lon, color: c, r: 3, born });
      world.arcsData(arcs).ringsData(rings);
    },
    focus(lat, lon) {
      controls.autoRotate = false;
      world.pointOfView({ lat, lng: lon, altitude: 1.6 }, 1200);
      clearTimeout(this._resume);
      this._resume = setTimeout(() => { controls.autoRotate = true; }, 8000);
    },
  };
}
