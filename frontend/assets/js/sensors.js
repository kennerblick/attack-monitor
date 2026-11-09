// Sensoren: 3lis.de selbst und die Außensensoren (sensors.json auf dem Server). Jeder Sensor hat eine feste
// Farbe, die überall gleich bleibt: Karte, Feed-Plakette, Globus-Beschriftung und Einschlag-Ring.
import { esc } from "./format.js";

export const LOCAL = "3lis";
// Bewusst außerhalb der Typ-Palette (format.js), damit Sensor- und Angriffsfarben nicht verwechselt werden
const COLORS = ["#4fd1ff", "#ffb547", "#c792ff", "#7ee081"];

let sites = [{ name: LOCAL, label: "3lis.de" }];

// list: [{name, lat, lon, label}], [0] = 3lis.de
export function setSensors(list) { sites = list.map((s, i) => ({ ...s, color: COLORS[i % COLORS.length] })); }
export const sensorSites = () => sites;
const site = name => sites.find(s => s.name === (name || LOCAL));
export const sensorName = name => site(name)?.label || name;
export const sensorColor = name => site(name)?.color || COLORS[0];
export const multiSensor = () => sites.length > 1;

export const sensorBadge = name =>
  `<span class="sb" style="--s:${sensorColor(name)}">${esc(sensorName(name))}</span>`;
