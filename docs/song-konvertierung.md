# Konzept: Echte Songs in Groove-Machine-Patterns umwandeln

Stand 2026-10-20 · Status: Konzept, nicht umgesetzt

## Ziel

Aus einem echten Song ein spielbares Groove-Machine-„Genre“ erzeugen: Tempo, Tonart, Drum-Muster,
Bass-, Akkord- und Melodielinie als Strudel-Spuren, Songteile (Intro, Drop, Break) als Varianten.
Das Ergebnis ist eine Annäherung zum Weiterspielen und Remixen, keine Kopie des Originals.

## Quellen und Rechtslage

| Quelle | Möglich? | Begründung |
|---|---|---|
| **Audiodatei vom Nutzer** | ja (empfohlen) | eigene Aufnahmen oder Dateien, an denen der Nutzer die Rechte hat |
| YouTube-Link | nur Metadaten | Herunterladen verstößt gegen die YouTube-Nutzungsbedingungen, bei fremden Songs meist auch gegen das Urheberrecht. Erlaubt ist nur der Titel über oEmbed. |
| Spotify-API | nur Metadaten | liefert kein Audio; `audio-features`/`audio-analysis` (BPM, Tonart) seit 27.11.2024 für neue Apps gesperrt, `preview_url` meist leer |

**Entscheidung:** Analysiert wird nur eine hochgeladene Audiodatei. Ein YouTube- oder Spotify-Link
dient höchstens dazu, Titel und Künstler vorzubelegen. Die Datei wird direkt nach der Analyse gelöscht.
Gespeichert wird nur das erzeugte Pattern.

## Pipeline

1. **Upload** (Browser → Backend): MP3/WAV/FLAC, höchstens 20 MB und 10 Minuten, Prüfung per `ffprobe`.
2. **Stem-Trennung:** Demucs (`htdemucs`, MIT) trennt Drums, Bass, Other und Vocals.
3. **Raster:** Tempo und Beat-Grid mit `librosa.beat` bzw. madmom, Tonart mit Essentia `KeyExtractor`.
   Alles wird auf 16tel pro Takt quantisiert.
4. **Spuren extrahieren:**
   - Drums: Onsets im Drum-Stem, nach Frequenzband klassifiziert (Kick < 150 Hz, Clap/Snare Mitten,
     Hats > 6 kHz) → `s("bd ~ ~ ~ …")`
   - Bass und Lead: Basic Pitch (Spotify, Apache-2.0) auf Bass- bzw. Other-Stem → MIDI → Noten
   - Akkorde: Chroma-Template-Matching (Dur/Moll/7) je Takt → Akkord-Stab bzw. Fläche
5. **Abstrahieren:** Noten werden in Skalenstufen relativ zur erkannten Tonart umgerechnet. So passen
   sie auf die Platzhalter `{K}`/`{S}`, und Tonart-Buttons transponieren weiterhin. Je Songteil wird die
   häufigste Schleife (1–4 Takte, Self-Similarity-Matrix) übernommen statt des ganzen Verlaufs.
6. **Ausgabe:** ein Objekt im Format von `frontend/strudel/genres/*.js` (`tracks`, `variants` = Songteile)
   als JSON. Das Frontend lädt es als zusätzliches Genre „Import: <Titel>“, gespeichert in IndexedDB wie
   die eigenen Samples.

## Architektur

- Eigener Dienst `song-import` (Python, systemd), **nicht** im Attack-Monitor-Prozess. Dieser läuft
  als root, die Analyse aber unter einem eigenen, unprivilegierten Benutzer mit `ProtectSystem=strict`.
- API: `POST /api/song` → Job-ID, `GET /api/song/<id>` → Status bzw. Ergebnis. Eine Warteschlange mit
  höchstens einem Job gleichzeitig (Demucs braucht auf CPU rund 1–3 Minuten pro Song und 2–4 GB RAM).
- Hinter Authelia, weil die Analyse teuer ist und Uploads sonst missbraucht werden können.
- Neue Abhängigkeiten: `demucs` (PyTorch, ca. 2 GB), `librosa`, `essentia`, `basic-pitch`, `ffmpeg`.
  Vorher die Ressourcen des Servers prüfen. Alternativ läuft der Dienst auf einem Homelab-Host, und
  3lis.de leitet nur weiter.

## Aufwand (Schätzung)

| Phase | Inhalt | Aufwand |
|---|---|---|
| 1 | Tempo, Tonart, Drum-Muster ohne Stem-Trennung (librosa) | 1–2 Tage |
| 2 | Demucs + Basic Pitch: Bass- und Lead-Spur | 2–3 Tage |
| 3 | Akkorde, Songteile als Varianten, Import-UI | 2 Tage |

Phase 1 liefert schon einen brauchbaren Groove. Danach entscheiden, ob sich die schwere
ML-Abhängigkeit lohnt.

## Grenzen

- Dicht produzierte Songs (Flächen, Effekte, Vocals) erkennt die Analyse nur grob; elektronische Musik
  mit klaren Loops funktioniert am besten, Kalkbrenner etwa gut, Rock oder Klassik schlecht.
- Klangfarben werden nicht nachgebaut; die Spuren nutzen die Synths und Drum-Machines der Groove Machine.

## Offene Entscheidungen

- Server: 3lis.de oder ein Homelab-Host für die Analyse?
- Wie viele Nutzer: nur Admin (Authelia) oder öffentlich mit Rate-Limit?
