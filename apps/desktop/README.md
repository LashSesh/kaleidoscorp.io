# Windows-Desktop: lesende Diagnose

Der Tauri-2-Host bündelt `ui/desktop` und stellt ausschließlich
`get_panel_snapshot_v2` bereit. Der Aufruf liest `GetStatus` über
`ssk-desktop-client` vom lokalen `sskd`. Die App startet keinen Dienst und bietet
keine Aktivierung, Firewall-, Routing- oder VPN-Steuerung.

## Bauen und starten

Voraussetzungen: Rust mit MSVC-Werkzeugen und Windows SDK, Node 22 oder neuer,
installiertes Microsoft WebView2. Aus dem Repository-Stamm:

```powershell
npm --prefix ui/desktop run build
cargo build --manifest-path apps/desktop/Cargo.toml --locked -j 2
.\apps\desktop\target\debug\ssk-desktop.exe
```

Der Host hat einen eigenen Cargo-Workspace und ein eigenes `Cargo.lock`. Der
Kern-Workspace zieht dadurch keine Tauri-/WebView-/GTK-Abhängigkeiten ein. Für
Layoutänderungen reicht weiterhin `npm --prefix ui/desktop run dev`; ein neues
Desktop-Binary erfordert zuerst den UI-Paketierungsschritt und dann den Rust-Build.
Ein Tauri-CLI- oder npm-Installationsschritt ist nicht erforderlich.

Die Standardverbindung verwendet denselben benutzerbezogenen Zustandspfad wie
die CLI. Ein absoluter `SSK_STATE_DIR` kann vor dem Start gesetzt werden und muss
zum separat gestarteten Daemon passen. Ein relativer Pfad wird abgewiesen.
Ohne erreichbaren Daemon erscheint „Daten nicht verfügbar“. Der normale
Browser-Einstieg ohne Host zeigt „Nicht verbunden“.

Das Ergebnis ist ein unsigniertes Entwicklungs-Binary für Windows. Installer,
Updater, Signierung und Freigabeprozess fehlen noch. Das kleine Entwicklungssymbol
kann mit `node apps/desktop/tools/icon.mjs` identisch neu erzeugt werden.

## Prüfen

```powershell
npm --prefix ui/desktop test
cargo test -p ssk-desktop-client -p ssk-ui-contract -p ssk-tauri-bridge --locked
cargo test -p ssk-daemon --test desktop_read --test dependency_closure --locked
cargo test --manifest-path apps/desktop/Cargo.toml --locked
```

Der zusätzliche Starttest öffnet kurz die eigene Desktop-Test-App, verwendet einen
isolierten synthetischen Pipe-Gegenpart und beendet seinen eigenen Prozess. Er
benötigt eine interaktive Windows-Sitzung mit WebView2 und ist standardmäßig ignoriert:

```powershell
cargo test --manifest-path apps/desktop/Cargo.toml --locked --test webview_status -- --ignored
```

Dieser Test prüft den vollständigen Aufrufweg vom gebündelten JavaScript bis zur
Pipe, jedoch keine Pixel oder native Bedienung. Ein separater Integrationstest
prüft denselben Leseadapter gegen den tatsächlichen Daemon. Die Darstellung kann
mit dem ausdrücklich als Beispiel markierten Szenario „Dienststatus (v2)“ im
Browser überprüft werden.

[Vertrauensgrenzen und nächste Schritte](../../docs/DESKTOP_BACKEND_CONNECTION.md).
