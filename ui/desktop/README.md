# Eigenständige Desktop-Oberfläche

Dieses Paket enthält Darstellung und Präsentationslogik. Entwicklung und Tests
benötigen Node.js 22 oder neuer, keinen Rust-Build, Windows-Dienst oder Tauri.
Es gibt keine npm-Abhängigkeiten und keinen Installationsschritt.

Aus dem Repository-Stamm:

```powershell
npm --prefix ui/desktop test
npm --prefix ui/desktop run dev
```

- [Vorschau mit Beispieldaten](http://127.0.0.1:5173/preview.html): acht auswählbare
  Zustände, dauerhaft als Vorschau gekennzeichnet.
- [Anwendungseinstieg](http://127.0.0.1:5173/): zeigt ohne Desktop-Host „Nicht verbunden“.

Der Entwicklungsserver bindet ausschließlich an IPv4-Loopback. Er liefert
statische Dateien und hat keine Backend-/Steuerungsendpunkte. Mit Strg+C beenden;
optional wählt `SSK_UI_PORT` einen anderen Port. Er ist kein auszuliefernder
Produktserver. ES-Module benötigen HTTP; HTML nicht per Doppelklick öffnen.
Dateiänderungen erfordern Neuladen, einen Rust-Neustart brauchen sie nicht.

## Wo Änderungen hingehören

| Bereich | Dateien | Abhängigkeit |
| --- | --- | --- |
| Layout / Stil | `index.html`, `preview.html`, `styles.css` | Browser |
| Fachliche Ansichten | `src/components/` | Anzeigemodell und DOM |
| Anzeigezustand / Aktualität | `src/controller.js`, `src/presentation.js` | injizierte Datenquelle |
| JSON-Prüfung | `src/contract.js` | versionierter Vertrag |
| Desktop-Anbindung | `src/transports/tauri.js` | injizierte Invoke-Funktion |
| Entwicklungsszenarien | `fixtures/`, `src/transports/preview.js` | nur Vorschau |
| Rust-Datenvertrag | `../../crates/ssk-ui-contract/` | Serde, keine Systemmodule |

Der Produktions-Importgraph erreicht keine Vorschau. Komponenten importieren
keinen Transport und rufen weder Tauri noch Netzwerkfunktionen direkt auf.
Architekturtests halten diese Grenzen fest. Die Legacy-HTML/JS/CSS-Dateien in
`ssk-tauri-bridge/ui` wurden durch dieses Paket ersetzt.

Nach drei Sekunden ohne Antwort wechselt die Ansicht zu „Daten nicht verfügbar“.
Zehn Sekunden nach Empfang werden die Daten entfernt und als veraltet markiert.
Das begrenzt das Alter in der Oberfläche; es bestätigt weder Quellaktualität noch
Herkunft. Manuelles Aktualisieren lädt eine neue vollständige Beobachtung.

Der [Windows-Desktop-Host](../../apps/desktop/README.md) implementiert
`get_panel_snapshot_v2` und liest den echten Daemon-Status. Der Build-Befehl
`npm --prefix ui/desktop run build` paketiert nur die Produktionsdateien für diesen
Host. Die zusätzliche Dienstkarte lässt sich mit „Dienststatus (v2)“ unabhängig
vom Backend gestalten. Die Desktop-Anbindung aktiviert keine Systemaufnahme,
Firewall- oder VPN-Funktion.

[Vertrag, Modulgrenzen und weitere Integration](../../docs/MODULAR_DESKTOP_UI.md).
