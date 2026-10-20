// Eigene Samples: Audiodateien bleiben im Browser (IndexedDB), Sample-Bänke per URL/GitHub (localStorage).
// Beides wird über window.samples() bei Strudel registriert und ist dann per s("name") spielbar.
// Nichts davon geht an den Server von 3lis.de.
const DB_NAME = "groove-samples";
const STORE = "files";
const URL_KEY = "groove-sample-urls";
const CODE_KEY = "groove-own-code";
const MAX_BYTES = 10 * 1024 * 1024;

const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
export const sampleName = filename =>
  filename.replace(/\.[^.]+$/, "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "sample";
export const validBank = url => /^github:[\w.-]+\/[\w.-]+(\/[\w./-]+)?$/.test(url) || /^https:\/\/\S+$/.test(url);

function store(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE, { keyPath: "name" });
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
    };
  });
}

const readJson = (key, fallback) => { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } };
const writeJson = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* privater Modus */ } };

// own: { on, code } im Bedienzustand; onChange baut das Pattern neu; status(text, cls) meldet Fehler
export function createOwnSamples({ own, onChange, status, el }) {
  let files = [];
  let urls = readJson(URL_KEY, []);
  own.code = readJson(CODE_KEY, "");

  const register = list => list.length &&
    window.samples(Object.fromEntries(list.map(f => [f.name, [URL.createObjectURL(f.blob)]])));

  function render() {
    el.list.innerHTML = [
      ...files.map(f => `<li><button class="own-name" data-name="${esc(f.name)}" title="Ins Pattern einfügen">${esc(f.name)}</button><button class="own-del" data-file="${esc(f.name)}" aria-label="Löschen">✕</button></li>`),
      ...urls.map(u => `<li class="bank"><span>${esc(u)}</span><button class="own-del" data-url="${esc(u)}" aria-label="Entfernen">✕</button></li>`),
    ].join("") || '<li class="empty">Noch keine eigenen Samples</li>';
    el.list.querySelectorAll(".own-name").forEach(b => { b.onclick = () => insert(b.dataset.name); });
    el.list.querySelectorAll("[data-file]").forEach(b => { b.onclick = () => removeFile(b.dataset.file); });
    el.list.querySelectorAll("[data-url]").forEach(b => { b.onclick = () => removeUrl(b.dataset.url); });
    el.code.value = own.code;
    el.on.checked = own.on;
  }

  // Leeres Pattern: Grundmuster anlegen; sonst den Namen an der Cursorposition einfügen
  function insert(name) {
    if (!own.code.trim()) own.code = `s("${name} ~ ${name} ~")`;
    else {
      const at = el.code.selectionStart ?? own.code.length;
      own.code = own.code.slice(0, at) + name + own.code.slice(at);
    }
    saveCode();
  }

  function saveCode() {
    writeJson(CODE_KEY, own.code);
    render();
    onChange();
  }

  async function addFiles(fileList) {
    const added = [];
    for (const file of fileList) {
      if (file.size > MAX_BYTES) { status(`${file.name}: größer als 10 MB`, "bad"); continue; }
      const entry = { name: sampleName(file.name), blob: file };
      await store("readwrite", s => s.put(entry));
      files = files.filter(f => f.name !== entry.name).concat(entry);
      added.push(entry);
    }
    await register(added);
    if (added.length && !own.code.trim()) insert(added[0].name);
    render();
  }

  async function removeFile(name) {
    await store("readwrite", s => s.delete(name));
    files = files.filter(f => f.name !== name);
    render();
  }

  async function addUrl(url) {
    url = url.trim();
    if (!validBank(url)) { status("Erwartet github:nutzer/repo oder eine https-URL auf eine strudel.json", "bad"); return; }
    try {
      await window.samples(url);
    } catch (err) {
      status(`Sample-Bank nicht ladbar: ${err.message}`, "bad");
      return;
    }
    urls = [...new Set([...urls, url])];
    writeJson(URL_KEY, urls);
    el.url.value = "";
    render();
    status(`Sample-Bank geladen: ${url}`, "ok");
  }

  function removeUrl(url) {
    urls = urls.filter(u => u !== url);
    writeJson(URL_KEY, urls);
    render();
    status("Entfernt; bereits geladene Sounds bleiben bis zum Neuladen der Seite verfügbar.");
  }

  el.files.addEventListener("change", e => { addFiles([...e.target.files]); e.target.value = ""; });
  el.add.onclick = () => addUrl(el.url.value);
  el.url.addEventListener("keydown", e => { if (e.key === "Enter") addUrl(el.url.value); });
  el.code.addEventListener("input", () => { own.code = el.code.value; writeJson(CODE_KEY, own.code); onChange(); });
  el.on.addEventListener("change", () => { own.on = el.on.checked; onChange(); });
  render();

  // Für prebake: gespeicherte Dateien und Bänke registrieren; Fehler einzelner Quellen brechen den Start nicht ab
  return async function load() {
    try {
      files = (await store("readonly", s => s.getAll())) || [];
      await register(files);
    } catch { files = []; }
    await Promise.all(urls.map(u => window.samples(u).catch(() => status(`Sample-Bank nicht ladbar: ${u}`, "bad"))));
    render();
  };
}
