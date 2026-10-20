// Live-Code-Ansicht: zeigt das laufende Programm und hebt hervor, welche Stellen gerade klingen.
// Strudel hängt an jedes Ereignis (Hap) die Zeichenpositionen seines Mini-Notation-Atoms
// (context.locations); wir fragen das Pattern pro Frame am aktuellen Zyklus ab.
const esc = s => s.replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

// ignore(text): Stellen, die zwar Patterns sind, aber nicht "klingen" (Drum-Bank, Skala)
export function createLiveView({ code, bar, beats, cycle, ignore = () => false }) {
  let text = "";
  let pattern = null;
  let scheduler = null;
  let lastKey = null;
  const beatEls = [...beats.children];

  function paint(ranges) {
    const key = ranges.map(r => r.join("-")).join(",");
    if (key === lastKey) return;
    lastKey = key;
    let html = "", pos = 0;
    for (const [start, end] of ranges) {
      if (start < pos) continue; // überlappende Stellen nur einmal markieren
      html += esc(text.slice(pos, start)) + `<mark>${esc(text.slice(start, end))}</mark>`;
      pos = end;
    }
    code.innerHTML = html + esc(text.slice(pos));
  }

  function activeRanges(t) {
    const ranges = [];
    for (const hap of pattern.queryArc(t, t + 1 / 1000)) {
      if (!hap.whole || hap.whole.begin.valueOf() > t) continue; // nur Ereignisse, die schon begonnen haben
      for (const loc of hap.context?.locations || []) {
        const start = loc.start ?? loc[0], end = loc.end ?? loc[1];
        if (end <= text.length && !ignore(text.slice(start, end))) ranges.push([start, end]);
      }
    }
    return ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  }

  function frame() {
    if (pattern && scheduler?.started) {
      const t = scheduler.now();
      const beat = Math.floor((t % 1) * 4);
      bar.textContent = `Takt ${Math.floor(t) + 1} · Schlag ${beat + 1}`;
      beatEls.forEach((el, i) => el.classList.toggle("on", i === beat));
      cycle.style.width = `${(t % 1) * 100}%`;
      try { paint(activeRanges(t)); } catch { paint([]); }
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  return {
    // Ohne Pattern (gestoppt): nur den Code zeigen, Positionsanzeige zurücksetzen
    show(newText, newPattern = null, newScheduler = null) {
      text = newText;
      pattern = newPattern;
      scheduler = newScheduler;
      lastKey = null;
      if (!pattern) {
        code.textContent = text;
        bar.textContent = "Takt –";
        beatEls.forEach(el => el.classList.remove("on"));
        cycle.style.width = "0";
      }
    },
  };
}
