// Genres mit ihren Spuren und Varianten (Subgenres). Platzhalter in den Patterns:
// {K} Grundton (z. B. "A"), {S} Skala, {B} Drum-Machine-Bank – "{K}1:{S}" wird zu "A1:minor".
// Eine Variante setzt Tempo, Bank, Skala und Grundton und ersetzt einzelne Spuren des Genres.
import techno from "./techno.js";
import house from "./house.js";
import dnb from "./dnb.js";
import lofi from "./lofi.js";
import synthwave from "./synthwave.js";
import ambient from "./ambient.js";

export const GENRES = [techno, house, dnb, lofi, synthwave, ambient];
export const KEYS = ["C", "D", "E", "F", "G", "A", "B"];
// Tasten für die Spuren 1–12 (zwei Reihen wie auf einem Pad-Controller)
export const PAD_KEYS = ["q", "w", "e", "r", "t", "z", "a", "s", "d", "f", "g", "h"];

export const trackCode = (genre, variant, key) =>
  variant.tracks[key] ?? genre.tracks.find(t => t.key === key).code;
