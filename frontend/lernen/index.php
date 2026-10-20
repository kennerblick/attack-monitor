<?php
// Konfiguration pro Verzeichnis (optional, sonst wird Verzeichnisname genutzt)
$meta = [
    'elements' => [
        'title'       => 'Periodensystem',
        'icon'        => '⚗️',
        'description' => 'Interaktives Lernen mit den chemischen Elementen',
        'color'       => '#e67e22',
    ],
    'cell' => [
        'title'       => 'Zellbiologie',
        'icon'        => '🔬',
        'description' => 'Aufbau und Funktion der Zelle',
        'color'       => '#27ae60',
    ],
];

// Unterverzeichnisse automatisch einlesen
// Liegt unter /lernen/, die Lernseiten selbst eine Ebene höher im Webroot
$base = dirname(__DIR__);
$skip = ['attack-monitor', 'strudel', 'lernen', 'assets'];
$dirs = [];
foreach (glob($base . '/*/index.html') as $f) {
    $name = basename(dirname($f));
    if (in_array($name, $skip, true)) continue;
    $dirs[$name] = $meta[$name] ?? [
        'title'       => ucfirst($name),
        'icon'        => '📖',
        'description' => '',
        'color'       => '#3498db',
    ];
}
ksort($dirs);
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lernseiten – Übersicht</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            min-height: 100vh;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 3rem 1rem;
            color: #e0e0e0;
        }

        header {
            text-align: center;
            margin-bottom: 3rem;
        }

        header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: #fff;
            letter-spacing: 0.05em;
            text-shadow: 0 2px 10px rgba(0,0,0,.4);
        }

        header p {
            margin-top: 0.5rem;
            color: #94a3b8;
            font-size: 1.1rem;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1.5rem;
            width: 100%;
            max-width: 960px;
        }

        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 1.8rem;
            text-decoration: none;
            color: inherit;
            transition: transform 0.2s, box-shadow 0.2s, background 0.2s;
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
            backdrop-filter: blur(10px);
        }

        .card:hover {
            transform: translateY(-4px);
            background: rgba(255,255,255,0.1);
            box-shadow: 0 12px 40px rgba(0,0,0,.3);
        }

        .card-icon {
            font-size: 2.8rem;
            line-height: 1;
        }

        .card-accent {
            width: 40px;
            height: 4px;
            border-radius: 2px;
            margin-top: 0.2rem;
        }

        .card h2 {
            font-size: 1.35rem;
            font-weight: 600;
            color: #fff;
        }

        .card p {
            font-size: 0.9rem;
            color: #94a3b8;
            line-height: 1.5;
            flex-grow: 1;
        }

        .card-arrow {
            font-size: 0.85rem;
            color: #64748b;
            margin-top: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.3rem;
        }

        .card:hover .card-arrow {
            color: #cbd5e1;
        }

        footer {
            margin-top: 4rem;
            color: #475569;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <header>
        <h1>📚 Lernseiten</h1>
        <p>Wähle ein Thema zum Lernen</p>
    </header>

    <div class="grid">
        <?php foreach ($dirs as $dir => $info): ?>
        <a class="card" href="/<?= htmlspecialchars($dir) ?>/">
            <div class="card-icon"><?= htmlspecialchars($info['icon']) ?></div>
            <div class="card-accent" style="background: <?= htmlspecialchars($info['color']) ?>"></div>
            <h2><?= htmlspecialchars($info['title']) ?></h2>
            <?php if ($info['description']): ?>
            <p><?= htmlspecialchars($info['description']) ?></p>
            <?php endif; ?>
            <div class="card-arrow">Jetzt lernen →</div>
        </a>
        <?php endforeach; ?>

        <?php if (empty($dirs)): ?>
        <p style="color:#64748b; grid-column:1/-1; text-align:center; padding:2rem;">
            Noch keine Lernseiten vorhanden.
        </p>
        <?php endif; ?>
    </div>

    <footer><a href="/" style="color:inherit">3lis.de</a> · <?= count($dirs) ?> Lernseite<?= count($dirs) !== 1 ? 'n' : '' ?> verfügbar · <a href="/impressum.html" style="color:inherit">Impressum</a> · <a href="/datenschutz.html" style="color:inherit">Datenschutz</a></footer>
</body>
</html>
