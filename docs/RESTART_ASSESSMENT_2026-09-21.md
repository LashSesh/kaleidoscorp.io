# Wiedereinstieg und Produktreife — 21.09.2026

> **Fortsetzung am 22.09.2026:** Die unten dokumentierten Konfigurations- und
> Auditfehler sind inzwischen im Daemon behoben und durch Regressionstests über
> den echten Prozess bzw. echte Loopback-Verbindungen abgedeckt. Der Supervisor
> übernimmt den Konfigurationszustand; Aktivierungen benötigen einen dauerhaften
> Audit-Eintrag vor dem Connect und ein dauerhaftes Ergebnis vor `Protected`.
> Ein Auditfehler nach dem Connect schließt die Verbindung. Details und Grenzen
> stehen in `RUNBOOK.md`, die Ledger-Kompatibilität in `COMPATIBILITY_MATRIX.md`.
> Die folgende Bestandsaufnahme bleibt als Ausgangsbefund erhalten.
>
> Validierung der ersten Umsetzung: Windows-Gesamtlauf **1.150 bestanden,
> 0 fehlgeschlagen, 1 vorhandener Golden-Generator ignoriert**. Die fünf neuen
> Regressionstests decken Konfigurationsfehler, defekte/unerreichbare Ledger,
> Auditfehler nach dem Connect sowie erfolgreiche Aktivierung und Wiederanlauf
> ab. Der zuvor instabile Negativtest reserviert seinen Port jetzt ohne Listener,
> statt ihn vor dem Connect wieder freizugeben.

## Einschätzung

Kaleidoscorp besitzt eine substanzielle, ausführbare Rust-Basis. Der aktuelle Stand ist ein Entwicklungsstand mit realen Netzwerkadaptern, Windows-Steuerung und umfangreichen Tests. Ein durchgängiges Produkt zur Steuerung und Absicherung fremder Anwendungsdaten ist noch nicht vorhanden. Enterprise-Reife erfordert zuerst belastbare Sicherheits- und Betriebsverträge auf dem tatsächlich ausgeführten Netzwerkpfad.

Diese Bestandsaufnahme beruht auf dem lokalen Arbeitsbaum, Codeprüfung, einem frischen Windows-Build, der vollständigen Testsuite und zwei isolierten Fehlerfall-Reproduktionen. Sie ist kein vollständiges Security-Audit. Quellcode und bestehende lokale Änderungen wurden nicht verändert; es wurde nichts committed oder veröffentlicht.

## Arbeitsstand und Wiederaufnahme

- Das eigentliche Repository liegt eine Ebene unter dem geöffneten Arbeitsordner: `kaleidoscorp.io/`. Im äußeren Ordner existiert zusätzlich ein leeres Git-Repository. Git- und Cargo-Arbeit muss im inneren Repository erfolgen.
- Branch: `windows-hardening-p0-p3`. Letzter lokaler Commit: `69cfd57` vom 04.08.2026, „Windows hardening P0-P3: gate compile, close privilege escalations, ship a working control plane and privileged broker“.
- Vor dieser Bestandsaufnahme: **31 modifizierte, 2 gelöschte und 6 unversionierte Dateien**. Der verfolgte Diff umfasst 1.300 hinzugefügte und 273 entfernte Zeilen; die sechs neuen Dateien sind darin nicht enthalten.
- Die offenen Arbeiten betreffen insbesondere BCIK/Closure, Gate-Prädikate, Architekturentscheidungen ADR 0007/0008, die Trennung der Daemon-Abhängigkeiten und die Entfernung von `ssk-sim`. Das ist erhaltenswerte Vorarbeit, kein sauberer Ausgangscommit.
- 44 Workspace-Crates; 188 Rust-Dateien, davon 149 unter `src` mit rund 70.300 Zeilen einschließlich Kommentaren und eingebetteten Tests. Drei ausführbare Produkteinstiegspunkte: `ssk`, `sskd`, `ssk-svc`.
- Toolchain lokal vorhanden und verwendet: Rust/Cargo 1.95.0, `x86_64-pc-windows-msvc`.

Vor dem nächsten Implementierungsschritt sollten die vorhandenen Änderungen fachlich zusammenhängend geprüft und versioniert werden. Der heutige Bericht ist kein Ersatz für diese Diff-Prüfung.

## Produktbild und Architektur

Die jüngsten lokalen Entscheidungen beschreiben einen Windows-orientierten **Router für einzelne Anwendungsverbindungen**: Wintun als Capture-Ansatz, mehrere auswählbare Egress-Adapter und OpenVPN als zusätzlicher, separat orchestrierter Adapter. Vollständige Verkehrsabdeckung ist laut `P4_FULL_COVERAGE_FEASIBILITY.md` bereits als v1.0-Ziel festgehalten. Der erste Proxy-Datenpfad unten ist daher ein Zwischenmeilenstein und keine stillschweigende Reduktion dieses Ziels.

| Bereich | Tatsächlicher Stand | Bedeutung |
|---|---|---|
| Netzwerkpfad | `ssk → IPC → sskd → ssk-netadmin → ssk-netcore → Socket` | Reale Verbindung auf ein ausdrücklich angegebenes Ziel. |
| Adapter | Direct, SOCKS5, HTTP CONNECT, TLS und DNS-Auflösung sind implementiert und lokal getestet. | Wertvolle Bausteine; der Daemon nutzt bisher eine feste Referenzpolicy und synthetische Flow-Merkmale. |
| Entscheidungskern | `ssk-runtime`, BCIK, Gates, Tensor, Focus und Replay; separate CLI-Einstiege. | Eigenständiger Modell-/Analysepfad. ADR 0008 schließt ihn bewusst aus der Daemon-Abhängigkeitsmenge aus. |
| Windows-Privilegien | `ssk-svc` hostet tatsächlich den Broker; Named-Pipe-Authentifizierung, Autorisierung, Recovery und Statuspfade existieren. | Ältere Aussagen „Broker ohne Host“ sind überholt. Privilegierte Gesamtfunktion ist damit noch nicht auf einer sauberen VM nachgewiesen. |
| Datenaufnahme | Kein produktiver Proxy-Listener und kein angebundener TUN-Datenpfad gefunden. `EgressSession::transport_mut` hat keine Aufrufer. | Der aktuelle Aktivierungsbefehl verbindet; er transportiert noch keine fremden Anwendungsdaten. |
| GUI | Bibliothek `ssk-tauri-bridge`, View-Tests und statisches Panel vorhanden; keine vollständige Tauri-Anwendung. | Ein Desktop-Produkt muss noch integriert werden. |
| Auslieferung | Release-Workflow baut, archiviert anschließend aber Quellen und Dokumentation. | Keine fertige Distribution mit Installer, signierten Binärdateien, Update-/Rollback-Nachweis. |

**Architektur beibehalten:** ADR 0008 entscheidet ausdrücklich gegen eine Workspace-Aufteilung und für eine mechanisch getestete Trennung der Daemon-Abhängigkeiten. Ältere P5-Aufträge zur Auslagerung der Theorie-Crates sind damit überholt. Weitere Theorieentwicklung liegt außerhalb des kritischen Pfads zum ersten echten Datenfluss.

## Heute ausgeführte Prüfungen

Das mitkopierte `target/` enthielt Programme mit eingebetteten absoluten Pfaden nach `C:\Users\stobe\Desktop\Projects\kaleidoscorp.io`. Der erste Lauf gegen diesen Cache scheiterte deshalb unter anderem beim Auffinden von Programmen und Fixtures. Ein kompletter Neubau in `target/restart-audit/clean-build` beseitigte diese Pfadfehler, ohne Quelldateien anzupassen.

| Prüfung | Ergebnis |
|---|---|
| `cargo fmt --all -- --check` | Bestanden. |
| `cargo build --workspace --all-targets --offline --locked` mit frischem Target-Verzeichnis | Bestanden. |
| `cargo clippy --workspace --all-targets --offline --locked -- -D warnings` mit demselben Target-Verzeichnis | Bestanden. |
| `cargo check -p ssk-types -p ssk-core --no-default-features --offline --locked` | Bestanden. |
| `cargo test --workspace --offline --locked --no-fail-fast` mit frischem Target-Verzeichnis | **1.143 bestanden, 2 fehlgeschlagen, 1 ignoriert**, 126 Ergebnisblöcke einschließlich Doc-Tests. |
| Gezielte Wiederholung des fehlgeschlagenen Profil-ACL-Tests außerhalb der Sandbox | Bestanden. Der erste Fehler war ein verweigerter Lesezugriff der Ausführungsumgebung. Keine Verzeichnisrechte geändert. |
| Gezielte serielle Wiederholung von `activate_with_no_route_fails_closed` | Bestanden. Im Gesamtlauf kam unerwartet `Protected` zurück. Der Test gibt seinen vermeintlich unerreichbaren Port vor dem Verbindungsversuch frei; eine Wiederbelegung ist möglich. **Flake-Verdacht, keine bewiesene abschließende Ursache.** |
| `git diff --check` | Bestanden. |

Damit ist die Build-/Lint-Basis gut; ein durchgehend grüner frischer Gesamttestlauf wurde heute **nicht** nachgewiesen. Das eine ignorierte Testprogramm ist der bereits vorhandene Golden-Generator. Keine Linux-/macOS-Ausführung, kein Release-Build, kein aktueller Advisory-Abgleich und keine privilegierte Firewall-/Treiber-/SCM-Abnahme durchgeführt.

Lokale Nachweise liegen im ignorierten Verzeichnis `target/restart-audit/`: `clean-tests.log`, `build.log`, `clippy.log`, `no-std.log`, `profile-acl-rerun.log`, `no-route-rerun.log`, `failure-paths.json` und `probe-failure-paths.ps1`. Diese Dateien gehören nicht automatisch zu einem späteren Git-Commit.

## Priorisierte Produktlücken

### 1. Ungültige Konfiguration verhindert Aktivierung nicht — reproduziert

`ssk-daemon/src/main.rs:245–280` lädt die Konfiguration, verwirft aber das Ergebnis. Auch der Fehlerzweig erzeugt lediglich einen Logeintrag; `Supervisor::new` erhält keinen Konfigurationszustand. `supervisor.rs:172` und `:541` benutzen stattdessen fest eingebaute Regeln.

**Reproduktion:** Frischen Daemon mit `SSK_CONFIG_PATH` auf eine syntaktisch ungültige TOML-Datei gestartet. Der Daemon protokolliert „config invalid“. Anschließendes `ssk --json activate --profile default --dest 127.0.0.1:<Testport>` liefert dennoch Exit 0 und `Protected`; der eigene Loopback-Listener bestätigt die reale Verbindung.

**Abnahme für die Behebung:** Status/Diagnose bleiben erreichbar, aber bei ungültiger Konfiguration erfolgt kein Dispatch und kein Verbindungsversuch. Gültige Regeln, Profile und Adapter müssen aus genau der validierten Konfiguration stammen. Dieser Fehler sollte vor Einführung weiterer Routingfunktionen geschlossen werden.

### 2. Auditfehler werden nach dem Verbindungsaufbau verschluckt — reproduziert

In `ssk-daemon/src/supervisor.rs:591–620` wird zuerst `Protected` gesetzt. Das anschließende `audit.record(...)` wird mit `.ok()` ausgewertet; ein Schreib-/Lesefehler ändert den Erfolg nicht.

**Reproduktion:** Im eigenen temporären Zustandsverzeichnis ein Verzeichnis namens `audit.json` angelegt, sodass der Ledger nicht als Datei nutzbar ist. Aktivierung liefert Exit 0, `Protected` und `audit_head: null`; die TCP-Verbindung entsteht tatsächlich. Eine Auditstörung wird im Aktivierungsergebnis nicht als solche gemeldet.

**Abnahme für die Behebung:** Auditpflicht und Verhalten bei Speicherfehlern ausdrücklich definieren. Für den beanspruchten Fail-closed-Betrieb muss fehlende dauerhafte Auditierbarkeit einen erfolgreichen Schutzstatus verhindern und die Verbindung sperren bzw. zurücknehmen. Fehler vor und nach dem Connect sowie Wiederanlauf benötigen eigene Nachweise.

Beide Versuche benutzten ausschließlich eigene Zustandsverzeichnisse, frische Programme und Loopback-Verbindungen. Die gestarteten Prozesse wurden beendet; Firewall, Routing, DNS-Einstellungen und Dienste wurden nicht verändert.

### 3. Attestierung wird am Dispatch nicht erzwungen — Codebefund

Der Planner liefert `RouteCandidate.requires_attestation`; der Supervisor reduziert den Kandidaten in `supervisor.rs:554–558` auf `candidate.route`. `DataPlane::connect_route` verlangt keinen Nachweis. ADR 0008 beschreibt bereits einen nicht öffentlich konstruierbaren `AdmissionToken`, dieser ist im aktuellen Quellcode noch nicht vorhanden.

Heute erzeugen die festen Regeln keine entsprechende Attestierungspflicht. Die Lücke wird wirksam, sobald konfigurierbare `RequireAttestation`-Regeln zugelassen werden. Deshalb zusammen mit, oder vor, der neuen Routing-Konfiguration schließen.

### 4. Schutzstatus und reale Schutzabdeckung müssen zusammenpassen

`Protected` beschreibt heute einen erfolgreichen einzelnen Egress-Handshake, keine systemweite Absicherung. Auch ein unerreichbarer privilegierter Broker kann gleichzeitig als `KILL_SWITCH_STATUS_UNKNOWN` gemeldet werden. Ein global beruhigender Status darf daraus im künftigen Produkt nicht entstehen.

Die erste Produktabnahme muss echte Bytes, die angewandte Regel, den tatsächlich verwendeten Adapter und den Auditnachweis zusammen prüfen. Für Vollabdeckung kommen TCP, UDP/QUIC, IPv4/IPv6, DNS, harte IP-Ziele, Prozesszuordnung, Netzwechsel und Ausfallverhalten hinzu. Noch unbekannte Prozesszuordnung muss als solche modelliert werden.

### 5. Betrieb und Skalierung brauchen eigene Nachweise

Der Supervisor hält seinen globalen Mutex während des Netzwerk-Connects. Das Dateiledger liest und schreibt bei jedem Append die gesamte Liste (`ssk-tensor/src/lib.rs:389–425`). Beides ist für einen einzelnen Aktivierungsvorgang nachvollziehbar, aber kein nachgewiesenes Modell für viele gleichzeitige Flows. Latenz, Speichergrenzen, Backpressure, Audit-Rotation und Wiederanlauf müssen vor breiter Nutzung gemessen bzw. festgelegt werden.

Hash-Verkettung allein macht ein lokales Ledger nicht unveränderbar: `verify_against_head` existiert, während der Daemon `verify()` verwendet. Für die Erkennung abgeschnittener oder neu geschriebener Historie braucht es ein festgelegtes Vertrauensmodell und unabhängig geschützte Checkpoints.

## Reihenfolge für die Fortsetzung

| Meilenstein | Konkretes Ergebnis | Abnahmekriterium |
|---|---|---|
| 0 — Verlässlicher Ausgangspunkt | Vorhandenen Diff prüfen und versionieren; Dokumentrangfolge festhalten; Test-Port-Race klären. | Reproduzierbarer sauberer Build und stabiler Gesamttestlauf. |
| 1 — Sicherheitsvertrag im Daemon | Konfigurationszustand durchreichen; Auditfehler behandeln; Bedeutung von Schutzstatus festlegen; Admission-Nachweis erzwingen. | Negative End-to-End-Tests: ungültige Konfiguration, fehlender Nachweis oder Auditstörung können keinen erfolgreichen Schutzstatus erzeugen. |
| 2 — Erster vollständiger Datenfluss | Konfigurierbare Profile/Regeln/Adapter und lokaler Proxy-Eingang mit bidirektionalem Datentransport. | Echter Client erreicht Testziel über gewählten Adapter; Deny verhindert Ankunft; passende Auditspur vorhanden; Fehler führen nicht zu unbeabsichtigtem Direct-Fallback. |
| 3 — Vollständige Capture-Abdeckung | Wintun-/Stack-Entscheidung durch VM-Messung absichern; Routing-Ausnahmen, UDP, IPv6 und belastbare Prozesszuordnung integrieren. | Abdeckungsmatrix und Tests für Leaks, Broker-/Pump-Absturz, Suspend/Resume, Netzwechsel und Wiederherstellung auf Windows-VMs. |
| 4 — Betreibbares Produkt | Installationspfade und Rechte, signierte Artefakte, Update/Rollback, Diagnoseexport, Ressourcenbudgets, anschließend angebundene GUI. | Saubere Windows-Installation, Upgrade, Downgrade/Recovery und Deinstallation ohne zurückgelassene Netzwerksperren; dokumentierte Supportgrenzen. |

Privilegierte Validierung aus `OPERATOR_VM_VALIDATION.md` ist ein eigener Freigabenachweis. Sie gehört auf wegwerfbare en-US/de-DE-Windows-VMs. Die Auswahl eines Packet-Stacks sollte den dokumentierten Vergleichsmessungen folgen. Frühere Zeit- und Performanceangaben sowie externe Treiber-/Signaturbehauptungen wurden in dieser Bestandsaufnahme nicht neu verifiziert und sind keine aktuelle Planungszusage.

Für einen späteren Unternehmenseinsatz muss zusätzlich die konkrete Betriebsform festgelegt werden: einzeln verwalteter Desktop-Client oder zentral verwaltete Flotte. Richtlinienverteilung, Rollen, geschützte Zugangsdaten, revisionsfähiger Export und ein definierter Updatekanal sind je nach Zielgruppe Produktanforderungen; eine zentrale SaaS-Verwaltung ist durch den jetzigen Auftrag nicht beschlossen.

## Dokumente richtig lesen

1. **Quellcode plus aktuelle Messergebnisse** entscheiden über implementiertes Verhalten.
2. **ADR 0008** enthält die jüngste Entscheidung zur Trennung von Flow-Pfad und Entscheidungskern sowie zum Verbleib im gemeinsamen Workspace.
3. **`P4_FULL_COVERAGE_FEASIBILITY.md`** überholt den engeren Umfang und mehrere Annahmen von `P4_INGRESS_DESIGN.md`. Das Vollabdeckungsziel darf bei einer Fortsetzung nicht verloren gehen.
4. **`WINDOWS_PRODUCT_ROADMAP.md`** bleibt ein nützlicher Phasenplan, enthält jedoch ältere Bestandsaussagen. Beispielsweise existiert der P3-Broker-Host inzwischen im Code; P5 fordert eine später verworfene Workspace-Aufteilung.
5. **Root-Audits, Completion-Checklist und README** enthalten historische Behauptungen. „Kein `ssk-netcore`“, „kein Named-Pipe-Client“, „Broker ohne Host“ oder pauschal „kein unsafe“ sind keine verlässlichen Aussagen über den heutigen Arbeitsbaum. `ssk-winhost` ist ausdrücklich die FFI-Ausnahme.

Empfohlener nächster Implementierungsauftrag: **Meilenstein 1 mit den zwei heute reproduzierten Fehlerfällen beginnen**, danach den konfigurationsgesteuerten ersten Datenfluss aufbauen. So lässt sich jede weitere Fähigkeit an einem tatsächlichen Produktpfad abnehmen.


## Fortsetzung 2026-09-22 — Routing und OpenVPN

Der Daemon verwendet jetzt validierte v4-Routingprofile und Adapter statt der
fest eingebauten Referenzregeln. Ohne passende Regel bleibt eine Verbindung
verweigert. Der bisher verworfene Attestierungsbedarf verhindert nun den
Dispatch; `DataPlane::connect_route` verlangt ein nicht kopierbares AdmissionToken
mit festem Ziel und Route. Ein Verifizierer für vorgelegte Attestierungen ist
weiterhin offen. Ungültige neuere Konfigurationen können nicht mehr durch den
Legacy-Decoder unter Verlust von Einstellungen akzeptiert werden.

OpenVPN ist als eigener Adapter-/Routentyp vorbereitet. Eine Auswahl meldet
`OPENVPN_NOT_READY`, ohne Direktverbindung. Prozesssteuerung, Broker-Anbindung,
Interface-Bindung und echte VPN-Abnahme sind noch nicht implementiert. Details,
Migrationsverhalten, Beispiel und nächste Arbeitsschritte stehen in
[ROUTING_AND_OPENVPN_STATUS.md](ROUTING_AND_OPENVPN_STATUS.md).

Die oben beschriebene Bestandsaufnahme bleibt als Ausgangsbefund erhalten; die
heutigen Ergänzungen ersetzen ihre Aussagen zu fest eingebauten Daemon-Regeln
und zur fehlenden Erzwingung der Attestierung. Meilenstein 2 bleibt wegen fehlendem
Ingress und Datentransport unvollständig. Keine Enterprise- oder Vollschutzfreigabe.


Abnahme dieses Schritts: Windows-Gesamtlauf **1.159 bestanden, 0 fehlgeschlagen,
1 vorhandener Generator ignoriert**; Workspace-Build, Clippy mit `-D warnings`,
Formatprüfung und CLI-Lint der vollständigen OpenVPN-Beispielkonfiguration
bestanden. Nachweise: `target/restart-audit/routing-*.log` (lokal, ignoriert).


## Nächster OpenVPN-Schritt — Management-Steuerung

`ssk-vpnctl` ist jetzt als eigenständige Workspace-Bibliothek implementiert:
begrenzter Protokollparser, Management-Anmeldung, PID-Abgleich, Hold-Freigabe,
Zustandsmeldungen, Heartbeat und zeitlich begrenztes Stoppen/Wiederverbinden.
Reale Loopback-TCP-Tests prüfen den Dialog gegen eine unabhängige Testgegenstelle.
Fehler schließen den Management-Kanal; spätere CONNECTED-Meldungen heben den
Fehlerzustand nicht auf. Freitexte aus Servermeldungen werden verworfen,
Passwörter und Zwischenpuffer beim Freigeben überschrieben.

Die Bibliothek startet noch keinen OpenVPN-Prozess und ist noch nicht an Broker
oder Daemon angeschlossen. Der Zustand `ConnectedUnverified` erteilt keine
Netzwerkfreigabe; Management-EOF bestätigt kein OS-Prozessende. Der Daemon bleibt
bei `OPENVPN_NOT_READY`. Nächster Integrationsschritt ist die geschützte
Profil-/Prozessverwaltung im Broker, anschließend die geprüfte Tunnelbindung.
Details: [OPENVPN_MANAGEMENT.md](OPENVPN_MANAGEMENT.md).


Abnahme: **20 neue Tests**, vollständiger Windows-Lauf mit **1.179 bestanden,
0 fehlgeschlagen, 1 vorhandenem ignorierten Generator**. Workspace-Build aller
Targets, Clippy mit `-D warnings` und Formatprüfung bestanden. Die Abhängigkeiten
des Daemons bleiben unverändert. Lokale Nachweise: `vpnctl-tests.log`,
`vpnctl-focused.log`, `vpnctl-build.log`, `vpnctl-clippy.log` unter
`target/restart-audit/`. Keine echte VPN-Verbindung oder privilegierte VM-Abnahme.


## Fortsetzung 2026-09-22 — VPN-Profile und Prozessbesitz

Die nächste OpenVPN-Grundlage ist implementiert: ein strikt geprüftes
Profilformat, eine Windows-Profilablage mit Prüfung der Zugriffsrechte sowie
eine Prozessüberwachung, die Management-Verbindung und Betriebssystem-Prozess
auseinanderhält. Profile können keine zusätzlichen Skripte, Plugins, Dateipfade
oder frei formulierten OpenVPN-Anweisungen einschleusen. Schlüsselmaterial
erscheint nicht in Debug-Ausgaben oder Parserfehlern.

Der Windows-Prozess wird bereits beim Start einem Jobobjekt zugeordnet. Dessen
Schließen beendet den Kindprozess auch nach einem abrupten Tod des Besitzers;
weitere Kindprozesse sind gesperrt. Das wurde mit realen, harmlosen Testprozessen
geprüft. Die Ablageprüfungen verwenden echte Dateioperationen mit simulierten
ACL-Beobachtungen; eine SYSTEM-Installation ist damit noch nicht nachgewiesen.

**Validierung: 1.206 Tests bestanden, 0 fehlgeschlagen, 1 bestehender Generator
ignoriert.** Hinzugekommen sind 27 Testfälle, darunter ein Prozess-Testhelfer.
Windows-Workspace-Build, Clippy mit `-D warnings`, Formatprüfung und Diff-Prüfung
sind erfolgreich. Linux-Kompilier- und Clippy-Prüfung der beiden betroffenen
Crates sind ebenfalls erfolgreich; Linux wurde nicht ausgeführt.

Der Daemon-Abhängigkeitsumfang steigt absichtlich auf 17 Crates, weil der
Windows-Host nun `ssk-vpnctl` verwendet. Entscheidungskern und Datenpfad bleiben
getrennt; die Architekturprüfung wurde passend dokumentiert und besteht.

**Noch offen:** vertrauenswürdig ausgewählte OpenVPN-Programmdatei, geprüfte
Management-Endpunktzugehörigkeit, kurzlebige Management-Schlüssel, autorisierte
und protokollierte Broker-Befehle, Profilinstallation/-rotation sowie geprüfte
Tunnel-, DNS- und Kill-Switch-Anbindung. Es gibt weiterhin keinen produktiven
VPN-Startbefehl; `OPENVPN_NOT_READY` bleibt korrekt. Es wurden weder ein echter
OpenVPN-Client noch ein VPN-Server oder eine privilegierte VM-Konfiguration
getestet. Details: [Profile und Prozessbesitz](OPENVPN_PROFILES_AND_PROCESS.md).

Lokale Nachweise: `target/restart-audit/vpn-owner-*.log`. Bei vollständigen
Windows-Builds `-j 2` verwenden; der erste Lauf erforderte das Bereinigen des
entbehrlichen inkrementellen Build-Caches nach einem Speicherplatzengpass.


## Fortsetzung 2026-09-22 — abgesicherter OpenVPN-Startablauf

Die bisherigen Bausteine sind jetzt zu einem durchgängigen Host-Ablauf verbunden.
Eine administrativ geschützte Freigabeliste bestimmt die zugelassene
OpenVPN-Programmdatei und sämtliche DLLs. Jede Datei wird anhand ihrer SHA-256
geprüft und während der Sitzung gegen Austausch gesperrt. Zusätzliche, fehlende,
manipulierte oder unsicher abgelegte Dateien führen zum Abbruch. Die Freigabeliste
muss aus einer überprüften Distribution stammen; eine Prüfsumme allein bestätigt
keine vertrauenswürdige Herkunft.

Der Host reserviert zuerst einen exklusiven lokalen Management-Port. Danach
erzeugt er ein frisches Passwort und geschützte Startdateien. Der gestartete
Prozess verbindet sich zurück; Windows muss die genaue Verbindung dem gehaltenen
Prozess zuordnen, bevor überhaupt Protokoll- oder Passwortdaten gesendet werden.
Andere Prozesse werden ohne Datenübertragung abgewiesen.

Das Ergebnis ist ausdrücklich **vorbereitet und angehalten**, nicht verbunden.
Der neue Ablauf besitzt keinen Befehl zum Aufheben dieser Sperre. Er überwacht
weiter die Erreichbarkeit und unterscheidet eine beendete Management-Verbindung
vom bestätigten Ende des Betriebssystem-Prozesses. Fehler beenden den Prozess;
die Rückmeldung zeigt, ob dessen Ende tatsächlich bestätigt werden konnte.

**Validierung: 1.221 Tests bestanden, 0 fehlgeschlagen, 1 bestehender Generator
ignoriert.** 15 Testfälle sind neu. Der gesamte Ablauf wurde mit einem separaten,
harmlosen Testprogramm als Management-Gegenstelle ausgeführt. Datei- und DLL-
Prüfsummen, Sperren, lokale TCP-Verbindungen, Windows-Prozesszuordnung und
Prozessbeendigung sind dabei echt; die ACL-Beobachtungen der Testablage werden
simuliert. Windows-Build, Clippy, Formatprüfung und Linux-Clippy der betroffenen
Crates sind erfolgreich. Der Architekturtest bestätigt weiterhin 17 Crates im
Abhängigkeitsumfang des Daemons und keinen zurückgekehrten Entscheidungskern.

**Nächste Etappe:** eigenständige VPN-Befehle und Zustände im Broker, passende
Benutzer-/Profilberechtigungen, dauerhaftes Vorgangsprotokoll und ein vom Dienst
verwalteter Überwachungs-Worker. Die vorhandenen Broker-Antworten und Journale
beschreiben ausschließlich den Kill Switch; sie wurden nicht als VPN-Erfolg
umgedeutet. Tunnel-Freigabe, Interface-Bindung, DNS, Firewall-Anbindung und
Abnahme mit einer echten OpenVPN-Distribution in einer Windows-VM bleiben offen.
`OPENVPN_NOT_READY` bleibt für produktive VPN-Routen korrekt.

Details und Manifestformat: [Abgesicherter Start](OPENVPN_SECURE_START.md).
Lokale Nachweise: `target/restart-audit/vpn-launch-*.log`.


## Fortsetzung 2026-09-22 — OpenVPN-Steuerung im Dienst

Der abgesicherte Start ist jetzt über eigene VPN-Befehle mit dem Windows-Dienst
und der CLI verbunden: `ssk winhost vpn status`, `prepare` und `stop`. Ein eigener
Worker übernimmt Start, laufende Überwachung und Prozessbeendigung. Die Sitzung
gehört dem Dienst und bleibt bestehen, wenn ein CLI-Aufruf endet. OpenVPN bleibt
weiterhin in **HOLD**; die neue Schnittstelle besitzt keinen Freigabebefehl für
Tunnel oder Datenverkehr.

Eine zusätzliche geschützte Richtlinie erteilt Rechte ausdrücklich pro Windows-SID,
Profil und Aktion. Administrator-Mitgliedschaft oder ein Kill-Switch-Recht reichen
nicht aus. Fehlende oder unsichere VPN-Konfiguration deaktiviert diesen Bereich.
Der bestehende Kill-Switch behält seine eigene Autorisierung und Protokollversion;
VPN-Befehle können weder dessen Befehle auslösen noch dessen Halteansprüche
übernehmen oder beim Verbindungsende entfernen.

Vor jeder Vorbereitung und jedem Stopp wird die Absicht dauerhaft synchronisiert.
Das getrennte, begrenzte Journal hält anschließend Ergebnis und Zustandsänderungen
fest. Eine angenommene Anfrage ist ausdrücklich noch kein erfolgreicher Start.
Revisionen verhindern veraltete Änderungen; wiederholte Vorgänge sind an Benutzer,
Profil und Aktion gebunden. Ein Schreibfehler sperrt neue Änderungen und beendet
eine vorhandene Sitzung. Nach einem Absturz bleibt ein unklarer Vorgang zur
Untersuchung gesperrt. Der Dienst übernimmt niemals einen alten Prozess nur anhand
seiner PID und löscht keine Protokolle oder Startreste automatisch.

Beim Dienst-Stopp werden neue Aufträge abgewiesen, ein laufender Start abgebrochen
und der gehaltene Prozess beendet. Ein unbestätigtes Prozessende oder ein defektes
Journal führt zu einer Fehlerrückmeldung. Die CLI verlangt für Änderungen die
aktuelle VPN-Revision und gibt eine Vorgangskennung für sichere Wiederholungen aus.

**Validierung: 1.247 Tests bestanden, 0 fehlgeschlagen, 1 bestehender Generator
ignoriert; 26 Testfälle sind neu.** Der gesamte Workspace baut unter Windows,
Clippy mit `-D warnings` ist grün. Die betroffenen Broker-/Host-/CLI-Crates
bestehen auch die Linux-Compilerprüfung. Format- und Diff-Prüfung sind sauber.
Der Daemon bleibt bei 17 Workspace-Abhängigkeiten ohne Entscheidungskern im
Verbindungspfad.

Die Windows-Prüfungen verwenden echte Prozesse, Dateien, Sperren, TCP-Zuordnung
und Named Pipes. Das gestartete Programm ist ein harmloser Management-Testprozess;
ACL-Beobachtungen seiner temporären Ablage werden simuliert. Die Pipe-Prüfung läuft
unter demselben unelevierten Benutzer. Ein echter OpenVPN-Client, LocalSystem/SCM,
andere Benutzer, Treiber, Firewall-Regeln und Tunnelverkehr wurden nicht erprobt
oder auf dem Arbeitsplatz eingerichtet. Die Linux-Prüfung ist eine Compilerprüfung.
Dabei wurden auch drei Windows-spezifische Deklarationen im IPC-Client korrekt
begrenzt und eine bestehende Linux-Testwarnung bereinigt.

**Nächste Etappe:** unterstützte Wiederherstellung und Journal-Aufbewahrung,
Installation/Update einer freigegebenen OpenVPN-Distribution und Abnahme unter
LocalSystem in einer wegwerfbaren Windows-VM. Die Tunnel-Freigabe setzt zusätzlich
verifizierte Interface-Bindung, DNS-/Routing-Regeln und Kill-Switch-Anbindung voraus.
`OPENVPN_NOT_READY` bleibt deshalb für produktive VPN-Routen korrekt.

[Betrieb, Richtlinienformat und Grenzen](OPENVPN_BROKER_CONTROL.md).
Lokale Nachweise: `target/restart-audit/vpn-broker-*.log`.


## Fortsetzung 2026-09-22 — Wiederherstellung nach unterbrochenem VPN-Start

Die OpenVPN-Steuerung besitzt jetzt einen ausdrücklich berechtigten Befehl
`ssk winhost vpn recover <profil> --expected-revision <revision>`. Nach einem
unterbrochenen Vorgang darf er weitere Starts erst zulassen, wenn das Ende des
alten Prozesses nachgewiesen und seine private Startablage bereinigt wurde.
Absicht, Prüfergebnis und Fehler bleiben im vorhandenen Journal nachvollziehbar.
Die Berechtigung gilt pro Benutzer und Profil; bisherige Start-/Stopp-Rechte
werden nicht automatisch erweitert.

Dafür erzeugt der Windows-Dienst den Prozess zunächst angehalten im bestehenden
Job. Prozessnummer, Windows-Erstellungszeit und zufällige Kennung der Startdateien
werden dauerhaft geschrieben, bevor der Prozess weiterlaufen darf. Scheitert
dieser Schritt, wird der eigene Prozess beendet. Bei der Wiederherstellung wird
eine Prozessnummer ausschließlich lesend geprüft. Ein inzwischen anderer Prozess
an derselben Nummer wird nicht beendet oder übernommen. Ein noch lebender alter
Prozess oder eine fehlgeschlagene Prüfung hält die Sperre aufrecht.

Nach bestätigtem Prozessende werden ausschließlich die zwei zur protokollierten
Kennung gehörenden Dateien geprüft und über ihre geöffneten Handles gelöscht.
Fremde Dateien, Profile und Journal bleiben erhalten. Unsichere Zugriffsrechte,
Reparse-Punkte und Hardlinks werden abgewiesen; eine teilweise Bereinigung lässt
sich wiederholen. Ein gleichzeitiges Prozessende kann einen bereits angenommenen
Wiederherstellungsauftrag nicht überschreiben und die Startsperre vorzeitig lösen.

Die VPN-Schnittstelle verwendet jetzt Protokollversion 3; CLI und Dienst müssen
zusammen aktualisiert werden. Das getrennte Kill-Switch-Protokoll bleibt bei
Version 1. Der neue Dienst kann die bisherigen Journale samt unveränderten Hashes
lesen. Für alte unterbrochene Vorgänge ohne Prozessidentität und einen Absturz
zwischen Prozesserzeugung und Speicherung der Identität gibt es bewusst keine
Freigabe ohne Nachweis. Auch beschädigte Journale werden nicht automatisch
repariert oder gelöscht. Dafür fehlen noch geprüfte Betriebsverfahren.

**Validierung: 1.263 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 16 Testfälle sind neu.** Windows-Build für sämtliche Targets
und Workspace-Clippy mit `-D warnings` sind grün. Broker, Windows-Host und CLI
bestehen die Linux-Compilerprüfung inklusive aller Targets mit Clippy.
Format- und Diff-Prüfung sind sauber. Die bestehende Architekturprüfung für die
17 Workspace-Abhängigkeiten des Daemons besteht weiterhin.

Die Tests verwenden echte harmlose Windows-Prozesse und Dateihandles. Sie prüfen
unter anderem Ausführung erst nach Freigabe, abgewiesene Protokollierung,
Abbruch vor Freigabe, Prozessidentität, Wiederherstellung eines unterbrochenen
Journalverlaufs, Berechtigungen, Wiederholungen und konkurrierende Anfragen.
Der Journal-Absturzfall wird in einer temporären Ablage rekonstruiert; echte
abrupte Beendigung eines Prozessbesitzers wird separat von den bestehenden
Job-Tests geprüft. Temporäre ACL-Beobachtungen im Starttest sind simuliert.
Ein echter OpenVPN-Client, LocalSystem/SCM, Treiber oder Tunnelverkehr wurde
weiterhin nicht auf dem Arbeitsplatz eingerichtet oder aktiviert. Linux wurde
kompiliert, nicht ausgeführt.

Für die spätere Abnahme ist eine eigene [Windows-VM-Prüfmatrix](OPENVPN_VM_ACCEPTANCE.md)
angelegt. Sie kennzeichnet alle Prüfungen mit echtem OpenVPN und LocalSystem als
noch nicht durchgeführt. Die vorhandene CI prüft Windows/Linux; ein dedizierter
OpenVPN-VM-Runner fehlt in den untersuchten Skripten und Workflows.

**Nächste Etappe:** Installation/Update der freigegebenen OpenVPN-Distribution,
Journal-Aufbewahrung und ein Verfahren für Vorfälle ohne ausreichenden Nachweis.
Danach folgt die dokumentierte VM-Abnahme. Interface-Bindung, DNS-/Routing-Regeln
und Kill-Switch-Anbindung müssen vor einer Tunnel-Freigabe umgesetzt werden.
`OPENVPN_NOT_READY` bleibt deshalb für produktive VPN-Routen korrekt.

[Technischer Wiederherstellungsvertrag und Grenzen](OPENVPN_RECOVERY.md).
Lokale Nachweise: `target/restart-audit/vpn-recovery-*.log`.


## Fortsetzung 2026-09-22 — Begrenzte Journal-Aufbewahrung und Betriebsprüfung

Das VPN-Journal wird jetzt bei Erreichen seiner Dateigrenze in einer nächsten,
fortlaufend benannten Datei weitergeführt. Frühere Dateien bleiben unverändert
erhalten. Prüfsummen, Sequenznummern und Statusrevisionen bilden über alle Dateien
hinweg dieselbe Historie. Ein Dateiwechsel setzt weder die Berechtigungen noch
einen ungeklärten Wiederherstellungszustand zurück.

Die ursprüngliche Datei bleibt während des gesamten Dienstbetriebs gesperrt;
auch die übrigen Segmente werden gegen fremde Schreib-/Löschzugriffe gehalten.
Neue Dateien werden ausschließlich unter festen Namen angelegt und vor dem ersten
Datensatz auf sichere Ablage geprüft. Kollisionen, unsichere Zugriffsrechte,
Hardlinks, Reparse-Punkte, fehlende Zwischenstücke und beschädigte Datensätze
führen zur Ablehnung. Eine beim Absturz gerade angelegte, noch leere letzte Datei
kann dieselbe Kette fortsetzen. Teilweise geschriebene Datensätze werden nicht
automatisch abgeschnitten oder repariert.

Die Aufbewahrung ist auf 64 Dateien begrenzt, jeweils höchstens 20.000 Datensätze
und 16 MiB. Zusammen gelten damit maximal 1.280.000 Datensätze und 1 GiB;
die tatsächlich früher erreichte Grenze zählt. Neue Aufträge lassen Platz für
ihren eigenen Eintrag und acht maximal große Notfall-Einträge. Die Prüfung
berücksichtigt sowohl Dateigrößen als auch Eintragszahlen. Reicht die Kapazität
nicht, beginnt kein neuer Vorgang. Physische Schreibfehler bleiben gesonderte
Audit-Fehler und lösen die vorhandene sichere Prozessbereinigung aus.

Der neue Befehl `ssk --json winhost vpn journal-inspect` prüft bei vollständig
gestopptem Dienst die gesamte Kette und meldet Datensatzanzahl, letzten Zustand,
Prüfsumme, Dateibelegung und verbleibende Kapazität. Er setzt Zugriff auf die
geschützte Ablage voraus, legt keine fehlenden Dateien an und verändert keine
Nachweise. Beim Einlesen wird nur ein begrenzter Datensatz gleichzeitig gehalten;
der Umfang der Historie bestimmt weiterhin die Prüfzeit.

Bisherige Journal-Datensätze bleiben unverändert lesbar. Neue Einträge verwenden
Schema 2, damit ältere Dienstversionen die spätere Segmentierung nicht übersehen
können. Vor dem ersten Dateiwechsel muss ein solcher Eintrag in der Ursprungsdatei
stehen. Ist ein altes Journal dafür bereits vollständig ausgeschöpft, bleibt eine
geprüfte Migration erforderlich. Das VPN-Steuerprotokoll bleibt bei Version 3.

**Validierung: 1.277 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 14 Testfälle sind neu.** Windows-Build für alle Targets und
Workspace-Clippy mit `-D warnings` sind grün. Die betroffenen Broker-/Host-/CLI-Crates
bestehen die Linux-Compilerprüfung mit Clippy. Format- und Diff-Prüfung sind sauber;
auch die erzeugte CLI-Hilfe wurde geprüft. Die vorhandenen Tests mit harmlosen
Windows-Prozessen verwenden jetzt den segmentierten Produktionsspeicher über die
privaten ACL-Testzugänge. Eine echte OpenVPN-/LocalSystem-Abnahme wurde nicht
durchgeführt; am Arbeitsplatz wurden keine Dienste, Treiber oder Tunnel eingerichtet.

Damit ist die lokale, begrenzte Aufbewahrung umgesetzt. Externe Archivierung,
Wiederherstellung aus Backups, vertrauenswürdige externe Prüfsummenanker,
zeitbasierte Löschregeln und Kapazitätsüberwachung im laufenden Betrieb bleiben
offen. Die VM-Prüfmatrix enthält zusätzliche Fälle für Dateiwechsel,
Stromausfälle und Startzeiten mit voller Historie. Eine rein lokale Prüfkette
kann weiterhin keinen administrativ entfernten vollständigen Verlaufsschluss
oder eine vollständig ersetzte Historie beweisen.

**Nächste Etappe:** der Installations-/Updatepfad für die freigegebene
OpenVPN-Distribution und die geschützte Konfiguration. Die Betriebsverfahren für
Archivierung und Vorfälle ohne ausreichende Nachweise sowie die Windows-VM-Abnahme
bleiben vor einer unbeaufsichtigten Produktionsfreigabe erforderlich. Tunnel-Freigabe
und Netzwerkdurchsetzung sind weiterhin nicht aktiviert.

[Speicherformat, Betriebsprüfung und Grenzen](OPENVPN_JOURNAL_RETENTION.md).
Lokale Nachweise: `target/restart-audit/vpn-journal-*.log`.


## Fortsetzung 2026-09-22 — Kontrollierte OpenVPN-Paketübernahme und Updates

Die Windows-CLI kann jetzt die geschützte VPN-Ablage explizit bereitstellen,
ein unabhängig freigegebenes OpenVPN-Paket prüfen und übernehmen, eine Version
für künftige Starts auswählen und unterbrochene Versionswechsel aufklären.
Die Befehle heißen `package-provision`, `package-stage`, `package-inspect`,
`package-activate` und `package-reconcile` unter `ssk winhost vpn`.
Sie erfordern eine tatsächlich erhöhte Windows-Sitzung und verwenden die echten
Berechtigungsprüfungen. Ein laufender Besitzer des VPN-Journals schließt die
Paketoperationen aus; ungeklärte Prozesszustände verhindern Übernahme und Auswahl.

Die Übernahme verlangt die extern freigegebene SHA-256-Prüfsumme des vollständigen
Quellmanifests. Jede aufgeführte Programm-/DLL-Datei wird geprüft und aus dem
gesperrten Dateihandle in ein neu beanspruchtes geschütztes Verzeichnis kopiert.
Berechtigungen werden vor dem Schreiben geprüft, das Ergebnis danach erneut
gegen sämtliche Prüfsummen kontrolliert. Erst dann entsteht das fertige
Paketmanifest. Unvollständige Verzeichnisse und vorhandene Paketkennungen werden
nicht überschrieben. Die Übernahme verändert die aktive Auswahl noch nicht.

Die Auswahl verlangt zusätzlich die erwartete Prüfsumme des bisherigen aktiven
Manifests beziehungsweise ausdrücklich `none` für eine Erstinstallation. So
überschreibt ein Auftrag mit veraltetem Wissen keine inzwischen geänderte Auswahl.
Bisherige Pakete bleiben erhalten; Manifestkopien sichern die konkreten
Vorgänger-/Kandidatenbytes. Eine frühere vollständig übernommene Version kann
über denselben geprüften Auswahlpfad ausdrücklich wieder ausgewählt werden.

Vor dem Dateitausch wird die Absicht mit Windows-Benutzer-SID, zufälliger
Vorgangskennung und beiden Manifestprüfsummen dauerhaft protokolliert.
Nach dem Tausch müssen Dateirückprüfung, Paketprüfung und Abschlussprotokollierung
gelingen. Bei einem fehlenden Abschluss bleibt der Vorgang offen und verhindert
den Start des VPN-Dienstbereichs. Die explizite Aufklärung akzeptiert nur die
nachweislich intakte alte oder neue Auswahl; sie verändert ausschließlich das
Journal. Fremde Auswahl, beschädigte Pakete oder fehlende Nachweise bleiben
gesperrt. Ein Paketwechsel kann keinen ungeklärten Prozesszustand zurücksetzen.

**Validierung: 1.293 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 16 Testfälle sind neu.** Windows-Build für alle Targets und
Workspace-Clippy mit `-D warnings` sind grün. Broker, Windows-Host und CLI bestehen
die Linux-Compilerprüfung mit Clippy für alle Targets. Format-/Diff-Prüfung und
die erzeugten CLI-Hilfen sind geprüft. Die neue Windows-Testgruppe verwendet
echte temporäre Dateien, Sperren, Hardlinks und Dateitauschoperationen; nur die
Berechtigungsbeobachtungen werden privat simuliert. Geprüft sind unter anderem
veraltete Auswahl, beschädigte Quellen, Teilübernahmen, Schreibfehler vor/nach
der Auswahl und die Wiederaufnahme nach beiden Abbruchzeitpunkten.
Es wurde weder OpenVPN ausgeführt noch ein Dienst, Treiber oder Tunnel eingerichtet.

Dies ist die Paketebene, noch kein vollständiger Produktinstaller. Freigabeprozess
mit Herausgeber-/Signaturprüfung, Treiberverteilung, Konfigurations- und
Berechtigungsverteilung, Paketaufbewahrung/Bereinigung sowie tatsächliche
Berechtigungen und Stromausfallverhalten in der Windows-VM bleiben offen.
Die VM-Prüfmatrix enthält dafür acht neue, ausdrücklich noch nicht ausgeführte
Prüffälle. Produktive Tunnel-Freigabe und Netzwerkdurchsetzung bleiben ausstehend.

**Nächste Etappe:** ein kontrollierter Installationspfad für Profile und
Zugriffsrichtlinien, anschließend die noch fehlenden Betriebsverfahren und die
VM-Abnahme mit freigegebener OpenVPN-/Treiberdistribution. `OPENVPN_NOT_READY`
bleibt bis zur Umsetzung und Abnahme der Netzwerkdurchsetzung korrekt.

[Paketworkflow, Wiederherstellung und Grenzen](OPENVPN_PACKAGE_DEPLOYMENT.md).
Lokale Nachweise: `target/restart-audit/vpn-deployment-*.log`.


## Fortsetzung 2026-09-22 — Profile und Zugriffsrechte gemeinsam installieren

Die Windows-CLI kann jetzt eine vollständige VPN-Konfiguration mit Profilen und
ihren Benutzerrechten prüfen, geschützt übernehmen und für den nächsten
Dienststart auswählen. Die neuen Befehle heißen `config-stage`, `config-inspect`,
`config-activate` und `config-reconcile` unter `ssk winhost vpn`. Sie verwenden
die vorhandene geschützte Ablage und dieselbe dauerhafte Journal-Sperre wie
Paketupdates und Prozesssteuerung.

Profile und Rechte werden als ein gemeinsamer Stand gewechselt. Die Übernahme
prüft die extern erwartete Prüfsumme, die Vertraulichkeit der Quelldatei und alle
enthaltenen Profile und Berechtigungen. Unbekannte oder doppelte Felder bleiben
auch in verschachtelten JSON-Objekten Fehler. Jede Berechtigung muss auf ein
Profil desselben Dokuments verweisen. Eine Konfiguration ist auf 1 MiB und
32 Profile begrenzt; die bestehenden Einzelgrenzen gelten zusätzlich. Vor dem
ersten Schreiben werden die geerbten Zielberechtigungen geprüft, anschließend
werden die geschriebenen Bytes erneut gelesen und kontrolliert.

Die Auswahl erfordert die erwartete bisherige Prüfsumme. Absicht und Ergebnis
werden mit tatsächlicher Windows-Benutzer-SID und getrenntem Transaktionsziel
protokolliert. Schlüsselmaterial und Profilendpunkte gelangen weder in diese
Audit-Einträge noch in CLI-Berichte. Frühere Stände bleiben erhalten; ihre
ausdrückliche erneute Auswahl stellt sowohl damalige Zugangsdaten als auch
damalige Rechte wieder her. Eine leere verwaltete Konfiguration entzieht alle
VPN-Rechte, ohne auf alte Berechtigungen zurückzufallen.

Der Dienst nimmt jetzt zuerst die Journal-Sperre und lädt danach den dazu
passenden Konfigurationsstand. Zulässige Pipe-Benutzer, Berechtigungsprüfung und
Startprofil stammen für seine Laufzeit aus demselben Stand. Die aktive Datei
bleibt gesperrt, die Profile werden nicht bei jedem Start erneut aus unabhängigen
Dateien gelesen. Die bisherigen öffentlichen Start-Hilfsmethoden ohne
Audit-Rückmeldung wurden entfernt; der Produktionsstart erfolgt intern über
den autorisierten Broker und dessen Prozessidentitäts-Protokollierung.

Vor der ersten verwalteten Auswahl bleibt das frühere Profil-/Richtlinienformat
lesbar. Fehlende oder beschädigte einzelne Altprofile erlauben keine neue
Vorbereitung; gültige Status- und Wiederherstellungsrechte bleiben für die
Aufklärung alter Vorgänge erhalten. Nach der ersten verwalteten Auswahl hält
das Journal deren Prüfsumme fest: Löschen oder Verändern der aktiven Datei kann
dann keine alten Berechtigungen wiederbeleben. Ein unterbrochener Wechsel sperrt
den VPN-Dienstbereich bis zur passenden expliziten Aufklärung. Paket- und
Konfigurationsvorgänge können nicht gegenseitig als abgeschlossen erklärt werden.

**Validierung: 1.313 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 20 Testfälle sind neu.** Windows-Build für alle Targets und
Workspace-Clippy mit `-D warnings` sind grün. Broker, Windows-Host und CLI bestehen
auch die Linux-Compilerprüfung mit Clippy für alle Targets. Die Architekturprüfung
für die 17 Workspace-Abhängigkeiten des Daemons besteht weiterhin. Format-/Diff-
Prüfung und die erzeugten CLI-Hilfen sind geprüft. Windows-Tests verwenden echte
temporäre Dateien, Hardlinks, Sperren und Dateitauschoperationen, mit privat
simulierten Berechtigungsbeobachtungen. Linux wurde kompiliert, nicht ausgeführt.

Damit sind geprüfte lokale Paket- und Konfigurationswechsel vorhanden. Es gibt
weiterhin keinen vollständigen Produkt-/Treiberinstaller, keinen abgeschlossenen
PKI-/Zertifikats-Lebenszyklus und keine produktive Tunnel-Freigabe. Alte und
unterbrochene Konfigurationsdateien enthalten geschütztes, unverschlüsseltes
Schlüsselmaterial; geprüfte Aufbewahrung, Backup/Wiederherstellung und Bereinigung
stehen noch aus. Die VM-Matrix enthält acht zusätzliche, noch nicht ausgeführte
Konfigurationsprüfungen. Es wurden keine echten OpenVPN-Dienste, Treiber, Tunnel
oder Firewallregeln am Arbeitsplatz eingerichtet.

**Nächste Etappe:** die Betriebsdiagnose und Wiederherstellung aus geprüften
Beständen ausbauen und die Windows-VM-Abnahme vorbereiten. Fehlende Nachweise
werden weiterhin nicht durch Journal-Reset oder ungeprüfte Freigaben ersetzt.
`OPENVPN_NOT_READY` bleibt bis zur Umsetzung und Abnahme der Netzwerkdurchsetzung
korrekt.

[Konfigurationsformat, Migration und Betriebsablauf](OPENVPN_CONFIGURATION_DEPLOYMENT.md).
Lokale Nachweise: `target/restart-audit/vpn-configuration-*.log`.


## Fortsetzung 2026-09-22 — Konfiguration diagnostizieren und exakt wiederherstellen

Die Windows-CLI bietet jetzt `config-diagnose`, `config-restore` und
`config-restore-reconcile` unter `ssk winhost vpn`. Damit lässt sich eine fehlende
oder beschädigte aktive VPN-Konfiguration aus dem aufbewahrten Stand oder einer
separaten vertraulichen Kopie wiederherstellen. Maßgeblich ist ausschließlich die
zuletzt im geprüften Journal bestätigte Prüfsumme. Frühere Sicherungen mit anderen
Zugangsdaten oder inzwischen entzogenen Rechten werden nicht als Ersatz akzeptiert.

Die Diagnose verändert keine Dateien oder Audit-Einträge. Sie unterscheidet
fehlende, gültige, inhaltlich beschädigte, unsicher abgelegte, zu große und nicht
lesbare Dateien. Der Bericht enthält Prüfsummen, Journalzustand, offene Vorgänge
und den nächsten geeigneten Arbeitsschritt, aber keine Zugangsdaten, Schlüssel
oder Profilendpunkte. Ein beschädigtes Journal oder eine unsichere Ablage bleiben
ein Fehler; die Diagnose umgeht diese Prüfungen nicht.

Die Wiederherstellung verlangt sowohl die erwartete bestätigte Prüfsumme als auch
die erwartete aktuelle Beobachtung, bei fehlender Datei ausdrücklich `missing`.
Veraltete Erwartungen verhindern den Eingriff. Vorhandene beschädigte Bytes werden
zuerst unter einer neuen Vorgangs-ID geschützt erhalten, synchronisiert und erneut
geprüft. Danach entstehen die geschützte Ersatzdatei und der dauerhafte
Wiederherstellungsauftrag. Erst anschließend wird die aktive Datei ausgetauscht;
Erfolg wird nach erneuter Inhaltsprüfung und dauerhaftem Ergebniseintrag gemeldet.
Unsichere, übergroße oder nicht lesbare Dateien werden nicht zwangsweise ersetzt.

Ein unterbrochener Vorgang sperrt den VPN-Dienstbereich und weitere schreibende
Konfigurations-/Paketwechsel. Die explizite Aufklärung bestätigt nur den zuvor
beobachteten Zustand oder den exakt bestätigten Konfigurationsstand. Fehlende oder
veränderte Beweiskopien verhindern den Abschluss auch dann, wenn die aktive Datei
schon korrekt aussieht. Andere Inhalte, beschädigte Audit-Daten oder offene
Paket-/Konfigurationsauswahlen erhalten keine Sonderfreigabe.

Die Dateiwiederherstellung lässt den bestätigten Berechtigungsstand und alle
Prozessinformationen unverändert; nur die Audit-Revision steigt. Dadurch kann sie
auch bei einem ungeklärten früheren Prozessvorgang die benötigte Konfiguration
wieder verfügbar machen. PID, Erstellungszeit, Startkennung, Beendigungsnachweis
und Wiederherstellungsphase bleiben erhalten. Die anschließende normale
Prozessaufklärung braucht weiterhin die vorgesehenen Rechte und Betriebssystem-
Nachweise. Es gibt weder Journal-Reset noch automatischen Prozess-/Tunnelstart.

**Validierung: 1.328 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 15 Testfälle sind neu.** Windows-Build für alle Targets und
Workspace-Clippy mit `-D warnings` sind grün. Broker, Windows-Host und CLI bestehen
die Linux-Compilerprüfung mit Clippy für alle Targets. Die Architekturprüfung der
17 Workspace-Abhängigkeiten des Daemons besteht weiterhin. Format-/Diff-Prüfung
und die erzeugten Hilfen aller drei neuen CLI-Befehle sind geprüft.

Die Tests prüfen unter anderem Versionsbindung, veraltete Erwartungen, geschützte
Beweiskopien, alternative Quellen, Hardlinks/Dateigrößen/Zugriffsverweigerung,
unveränderte Prozessidentität, Abbrüche vor und nach dem Dateitausch sowie Fehler
bei Absichts- und Ergebnisprotokollierung. Windows-Dateien, Sperren und Dateitausch
sind real; Berechtigungsbeobachtungen werden privat simuliert. Linux wurde
kompiliert, nicht ausgeführt. Es wurden keine echten OpenVPN-Dienste, Treiber,
Tunnel oder Firewallregeln am Arbeitsplatz eingerichtet.

Dies ist die Wiederherstellung einer aktiven Konfigurationsdatei aus bereits
vorhandenen geprüften Bytes. Verschlüsselte Sicherungserstellung, vollständige
Systemwiederherstellung, Journalarchiv-Rückspielung mit externer Vertrauensbasis,
Aufbewahrung/Bereinigung geheimer Dateien und Verfahren für fehlende Nachweise
bleiben offen. Beweis- und temporäre Dateien können vertrauliches, durch ACLs
geschütztes Klartext-Schlüsselmaterial enthalten und werden nicht automatisch
gelöscht. Die VM-Matrix enthält sechs zusätzliche, noch nicht ausgeführte
Wiederherstellungsprüfungen; Stromausfallverhalten und reale Benutzer-/LocalSystem-
Berechtigungen sind damit noch nicht abgenommen.

**Nächste Etappe:** geschützte Sicherung und Aufbewahrung konkretisieren und einen
reproduzierbaren Ablauf für die Windows-VM-Abnahme vorbereiten. Die produktive
Tunnel-Freigabe bleibt bis zur Umsetzung und Abnahme der Netzwerkdurchsetzung
gesperrt; `OPENVPN_NOT_READY` ist weiterhin korrekt.

[Betriebsablauf, Abbruchfälle und Grenzen](OPENVPN_CONFIGURATION_RESTORE.md).
Lokale Nachweise: `target/restart-audit/vpn-restore-*.log`.


## Fortsetzung 2026-09-22 — Verschlüsselte Konfigurationssicherung

Die Windows-CLI kann jetzt einen separaten Wiederherstellungsschlüssel erzeugen,
die aktive bestätigte VPN-Konfiguration verschlüsselt sichern und ein Archiv
ohne Klartextausgabe prüfen. Die Befehle heißen `config-backup-key-create`,
`config-backup` und `config-backup-verify` unter `ssk winhost vpn`. Der vorhandene
`config-restore` akzeptiert zusätzlich `--backup` mit `--key-file`; die bisherige
vertrauliche Klartextquelle bleibt unterstützt. Beide Quellen durchlaufen denselben
Wiederherstellungsablauf mit Versionsbindung, Beweissicherung und Audit-Protokoll.

Der Schlüssel enthält 256 zufällige Bits aus der Betriebssystem-Zufallsquelle.
Archive verwenden XChaCha20-Poly1305 aus der bereits im Lockfile vorhandenen
RustCrypto-Bibliothek mit einer neuen zufälligen 192-Bit-Nonce je Sicherung. Der
gesamte Dateikopf einschließlich Version, Konfigurationsprüfsumme und Nonce wird
authentifiziert. Es gibt keine eigene Verschlüsselungsprimitive, Passwortableitung
oder zusätzliche Workspace-Abhängigkeit; lediglich die vorhandene Bibliothek
wird im Windows-Host direkt verwendet. Der Konfigurationsinhalt bleibt auf 1 MiB
begrenzt, das Archiv auf 1 MiB plus 80 Byte.

Schlüssel und Archive benötigen bereits vorhandene, vertrauliche administrative
Verzeichnisse mit geprüften Vorfahren. Dateien werden einmalig neu angelegt;
geerbte Berechtigungen werden vor dem Schreiben geprüft. Nach Synchronisation
folgen erneutes Lesen und Prüfen, beim Archiv einschließlich Entschlüsselung und
vollständiger Profil-/Rechteprüfung. Existierende oder unvollständige Dateien
werden nicht überschrieben. Unsichere Besitzer/Rechte, Hardlinks, Reparse-Punkte,
falsche Schlüssel, veränderte/trunkierte/übergroße Archive und unbekannte Formate
führen zur Ablehnung. Schlüsselwerte und Klartext erscheinen weder in Argumenten
noch in CLI-Berichten. Der Schlüssel selbst bleibt eine separat aufzubewahrende,
durch Dateirechte geschützte Klartextdatei.

Sicherung und Archivprüfung nehmen die bestehende Journal-Sperre. Sie benötigen
die ausdrücklich erwartete und im Journal bestätigte Konfigurationsprüfsumme;
offene Wartungsvorgänge oder ein ungesunder Audit-Zustand blockieren sie. Eine
ungeklärte Prozesshistorie mit gesundem Audit bleibt unverändert und verhindert
für sich genommen keine Sicherung. Zur Prüfung eines Archivs sind aktive oder
aufbewahrte Klartextprofile nicht erforderlich; das gesunde passende Journal
bleibt notwendig. Die Sicherungsberichte enthalten nur Aktion, Prüfsummen und
Dateigröße. Sie sind noch kein dauerhaftes Export-Audit: Sicherung/Prüfung schreiben
keine zusätzlichen Journal-Ereignisse. Die eigentliche Wiederherstellung nutzt
weiterhin die vorhandenen dauerhaften Absichts-/Ergebniseinträge.

Die Entschlüsselung für den Restore erfolgt im Speicher. Es entsteht keine
separate Klartext-Importdatei. Vor jeder Veränderung müssen Authentifizierung,
bestätigte Prüfsumme und Dokumentprüfung stimmen. Ein altes Archiv kann daher
nach einem neueren Konfigurationswechsel keine entzogenen Rechte zurückbringen.
Bestehende aktive, temporäre und Beweisdateien behalten ihren bisherigen
vertraulichen Klartext-Vertrag. Unterbrechungen werden über dieselbe explizite
Aufklärung behandelt; Prozessidentität und fehlende Beendigungsnachweise bleiben
erhalten. Journal- und Netzwerkprotokolle wurden nicht verändert.

**Validierung: 1.345 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 17 Testfälle sind neu.** Windows-Build für alle Targets,
Workspace-Clippy mit `-D warnings`, Format-/Diff-Prüfung und CLI-Hilfen sind grün.
Broker, Windows-Host und CLI bestehen die Linux-Compilerprüfung mit Clippy für
alle Targets. Die Architekturprüfung für die 17 Workspace-Abhängigkeiten des
Daemons besteht weiterhin.

Die neuen Tests prüfen tatsächliche Verschlüsselung und Rückgewinnung, frische
Nonces, Änderungen an jedem einzelnen Archivbyte, falsche Schlüssel, exakte
Maximalgröße, Authentifizierung bei gleichzeitig falschem Inhalt, alte Rechte,
unsichere/mehrfach verknüpfte Dateien, verweigerte Ausgabe vor dem Schreiben,
Kollisionen sowie unterbrochene Wiederherstellung mit ungeklärtem Prozessstatus.
Windows-Dateien/Sperren/Dateitausch sind real, Berechtigungsbeobachtungen privat
simuliert. Linux wurde kompiliert, nicht ausgeführt. Es wurden keine echten
OpenVPN-Dienste, Treiber, Tunnel oder Firewallregeln am Arbeitsplatz eingerichtet.

Die neue Betriebsdokumentation beschreibt getrennte Schlüsselverwahrung,
Archivinventar, erneute Prüfung nach Übertragung und die Aufbewahrung der zum
aktuellen Stand gehörenden Sicherung. Es gibt noch keine automatische Löschung,
Schlüsselrotation, HSM/KMS-Anbindung, externe Export-Protokollierung oder
Journalarchiv-Wiederherstellung. Ein verlorener Schlüssel wird nicht umgangen;
ein Konfigurationsarchiv allein ermöglicht keine vollständige Wiederherstellung
nach Verlust des ganzen Rechners. Verbindliche Aufbewahrungsfristen wurden nicht
erfunden. Sechs zusätzliche VM-Prüffälle sind ausdrücklich noch nicht ausgeführt.

**Nächste Etappe:** eine reproduzierbare, nachweisorientierte Windows-VM-Abnahme
vorbereiten und den verbleibenden Journal-/Betriebsprozess konkretisieren. Reale
Benutzerrechte, Schlüsselverwahrung und Stromausfälle sind noch nicht abgenommen.
Die produktive Tunnel-Freigabe und Netzwerkdurchsetzung bleiben offen;
`OPENVPN_NOT_READY` bleibt korrekt.

[Sicherungsformat, Schlüsselverwahrung und Betriebsablauf](OPENVPN_CONFIGURATION_BACKUP.md).
Lokale Nachweise: `target/restart-audit/vpn-backup-*.log`.


## Fortsetzung 2026-09-22 — Nachvollziehbare Windows-VM-Abnahme vorbereiten

Ein separates Werkzeug `ssk-vpn-acceptance` unterstützt jetzt die Erfassung und
Prüfung von Abnahmenachweisen. Es gehört zum bestehenden CLI-Paket und bietet
`matrix`, `init`, `record`, `report` und `check`. Der übliche Start über
`cargo run -p ssk-cli` bleibt durch `default-run = "ssk"` unverändert. Es gibt
keine zusätzliche Workspace-Abhängigkeit; SHA-256 wird aus der bereits vorhandenen
Bibliothek verwendet. Die vorhandenen Windows-/Linux-CI-Jobs bauen und testen
das zusätzliche Binary automatisch mit.

Der Katalog umfasst alle 49 Fälle der OpenVPN-Prüfmatrix mit jeweils benötigten
Nachweiskategorien. Ein Test gleicht die Fallkennungen mit der Dokumentation ab.
Jeder Lauf wird an VM-/Snapshot-Angaben, Windows-Version, Sprache, tatsächliche
Benutzer-SIDs, Quellstand, anfängliche Konfiguration sowie freigegebene
Distributions-/Treiberangaben gebunden. CLI, Dienstbinary und Abnahmewerkzeug werden
gelesen und mit Prüfsummen festgehalten, ohne sie auszuführen. Die Angaben zur
VM-Isolation und zu Testzugangsdaten müssen ausdrücklich bestätigt sein; alle
Fälle beginnen als noch nicht ausgeführt.

Ein Prüfversuch enthält Zeitangaben, eine tatsächliche Beobachtung und bis zu
acht geprüfte, bereinigte Textnachweise. Bestandene Fälle brauchen alle vorgesehenen
Kategorien, etwa CLI-, Rechte-, Journal-, Prozess-, Netzwerk- oder Abbruchnachweise.
J07, D08 und B06 bleiben wegen ihrer noch fehlenden Implementierungs-/Betriebs-
Voraussetzungen ausdrücklich für eine Bestehensmeldung gesperrt. Nachweise sind
auf 256 KiB je Datei und Läufe auf 256 Versuche begrenzt. Bekannte Schlüssel-/PEM-
Markierungen und Binärinhalt werden abgewiesen. Die Inhaltskontrolle ist nur eine
zusätzliche Schranke; die manuelle Prüfung auf vertrauliche Daten bleibt notwendig.

Jeder Versuch erhält ein neues nummeriertes Verzeichnis. Seine Dateien werden
einmalig angelegt, synchronisiert und durch den abschließenden Datensatz mit
Beobachtung, Laufkennung, vorherigem Stand, Dateigrößen und Prüfsummen verbunden.
Wiederholungen ergänzen die Historie; frühere Nachweise bleiben erhalten und werden
weiter geprüft. Für den aktuellen Fallstatus gilt das letzte Ergebnis, sodass
ein späterer Fehler einen früheren Erfolg nicht verdeckt. Fehlende, veränderte,
vertauschte, unerwartete oder unvollständige Dateien verhindern einen gültigen
Bericht und weitere Einträge. Angefangene Versuche werden nicht stillschweigend
entfernt, übersprungen oder als abgeschlossen behandelt.

Der gemeinsame Abschlusscheck verlangt einen en-US- und einen de-DE-Lauf mit
übereinstimmenden Binary-, Windows-, Quell-, Distributions- und Treiberständen.
Er prüft beide vollständigen Historien gegen separat aufbewahrte letzte Prüfsummen.
Unvollständige fachliche Abdeckung liefert Exitcode 3; ungültige Nachweise liefern
Exitcode 2. Erfolgreiche Erfassung oder ein strukturell gültiger Einzelbericht
sind ausdrücklich keine Test-/Produktfreigabe. `release_ready` bleibt in dieser
Etappe immer `false`. Lokal veränderbare Prüfsummen ersetzen weder externe
Vertrauensanker noch unabhängige Bestätigung der gemeldeten Beobachtungen.

Eine Betriebsanleitung und zwei bewusst noch nicht ausführbare JSON-Vorlagen
beschreiben Vorbereitung, getrennte Benutzerrollen, konkrete Nachweiskategorien,
Zeitangaben, Wiederholungen, Sprachvergleich und den Umgang mit Teilversuchen.
Das Werkzeug startet keine VPN-Prozesse oder Dienste, installiert keine Treiber,
ändert keine Rechte/Firewallregeln und löst keine Fehler aus. Hypervisor-/Debugger-
Verfahren für bestimmte Abbruchstellen sowie die tatsächliche VM-Bereitstellung
bleiben separate Arbeiten. Die VM-Fakten und Ergebnisse sind geprüfte Angaben
eines Bedieners; automatische VM-Erkennung oder Attestierung werden nicht behauptet.

**Validierung: 1.360 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 15 neue Tests wurden auf Windows ausgeführt.** Zwölf prüfen
Katalog, Laufbindung, unveränderte Historie, Teilversuche, veränderte/fehlende
Dateien, entfernte Historienenden, Größen-/Zeitgrenzen, vertrauliche Inhalte und
Sprachvergleich. Drei weitere starten das echte Abnahmewerkzeug mit ausdrücklich
synthetischen VM-Angaben und prüfen Erfassung, Fehlerausgaben und Exitcodes.
Ein zusätzlicher Unix-Symlink-Test ist in der Linux-Compilerprüfung enthalten,
wurde auf diesem Windows-Arbeitsplatz aber nicht ausgeführt.

Windows-Build für alle Targets, Workspace-Clippy mit `-D warnings`, Format-/Diff-
Prüfung und die erzeugten Hilfen sind grün. Die CLI samt Abnahmewerkzeug besteht
die Linux-Clippy-Prüfung für alle Targets. Die Architekturprüfung für die
17 Workspace-Abhängigkeiten des Daemons besteht weiterhin. Kein echter Fall der
OpenVPN-VM-Matrix wurde durch diese lokalen Werkzeugtests als bestanden erklärt.
Es wurden keine echten OpenVPN-Dienste, Treiber, Tunnel oder Firewallregeln am
Arbeitsplatz eingerichtet.

**Nächste Etappe:** die verfügbare isolierte VM-Umgebung und ihre Voraussetzungen
prüfen und den ersten fachlichen Durchlauf vorbereiten. Journal-Wiederherstellung
mit externer Vertrauensbasis, fehlende Betriebsverfahren und produktive Tunnel-
Durchsetzung bleiben offen. `OPENVPN_NOT_READY` bleibt weiterhin korrekt.

[Abnahmewerkzeug, Vorlagen und Ablauf](OPENVPN_ACCEPTANCE_TOOL.md).
Lokale Nachweise: `target/restart-audit/vpn-acceptance-*.log` sowie der ausgegebene
Katalog `target/restart-audit/vpn-acceptance-matrix.json`.

## Fortsetzung 2026-09-22 — Testumgebung geprüft und Entwicklungspaket erstellt

Der Nutzer hat bestätigt, dass noch keine separate Testumgebung vorhanden ist.
Die rein lesende Inventur des aktuellen Rechners liefert Windows 11 Home,
Build 26200, etwa 7,7 GiB nutzbaren Arbeitsspeicher, zum Prüfzeitpunkt etwa
1,4 GiB freien Arbeitsspeicher und 21,5 GiB freien Speicher auf C:. Die Suche
nach VM-Verwaltungsbefehlen und üblichen Installationspfaden blieb ohne Treffer.
Ein vorhandener Hypervisor und der laufende Dienst `vmcompute` belegen allein
keine verfügbare Windows-Test-VM. Es wurde keine VM eingerichtet oder gestartet.

`scripts/openvpn-vm-host-probe.ps1` macht diese Inventur wiederholbar. Es liest
OS-, Speicher- und Verwaltungsinformationen und meldet unbekannte Fakten als
unbekannt. Als Planungsreserve für einen lokalen Gast gelten 12 GiB Gesamtspeicher,
6 GiB freier Arbeitsspeicher und 96 GiB freier Laufwerksspeicher. Das sind eigene
Planungswerte, keine Hersteller-Mindestanforderungen und keine Anforderungen an
bereits bereitgestellte entfernte Gäste. Auch bei ausreichenden Ressourcen bleiben
`vm_ready` und `release_ready` ausdrücklich falsch. Das Skript ändert keine
Virtualisierungs-, Dienst-, Rechte- oder Netzwerkeinstellungen.

Das Abnahmewerkzeug bietet jetzt `kit-create` und `kit-verify`. Ein neues
Entwicklungspaket enthält ausschließlich die drei angegebenen Windows-x64-
Programme, fest eingebettete öffentliche Betriebsanleitungen/Vorlagen und die
Rechnerprüfung. Die Programmdateien werden über geöffnete Lesehandles kopiert,
synchronisiert und rückgelesen; das Manifest mit Dateigrößen und SHA-256-Werten
wird zuletzt geschrieben. Bestehende oder unvollständige Zielverzeichnisse
werden weder übernommen noch überschrieben. Profile, Schlüssel, Journale,
OpenVPN-Distribution und Treiber gehören nicht zum Paket.

Die Prüfung verlangt die separat aufbewahrte Manifest-Prüfsumme und die exakte
Datei-/Verzeichnisliste. Fehlende, zusätzliche, veränderte, übergroße oder über
Symlink/Reparse-Pfade erreichbare Einträge werden abgewiesen. PE-Kopfprüfung und
Hashes ersetzen keine Herausgebersignatur, reproduzierbaren Build oder Prüfung
der Laufzeitvoraussetzungen. Der Prüfer benötigt selbst eine vertrauenswürdige
Herkunft; das Paket begründet kein Vertrauen in sich selbst. Zugriffsrechte der
Transferablage werden nicht automatisch eingerichtet oder geprüft.

Das tatsächlich erstellte und erneut geprüfte Paket liegt unter
`target/restart-audit/openvpn-development-kit-2026-09-22/`. Es umfasst 19 Nutzdateien
mit insgesamt 27.164.800 Bytes plus Manifest. Es enthält die lokalen Debug-Builds,
ist unsigniert und ausdrücklich nur für Entwicklung vorgesehen. Der Quellstand
ist `69cfd572ed699210d36276e35f9d931d4a0273ae` mit `worktree_dirty: true`;
die konkreten Programme sind einzeln durch ihre Hashes bestimmt. Die Änderungen
im Arbeitsverzeichnis müssen weiterhin separat erhalten bleiben.

Die Manifest-Prüfsumme ist außerhalb des Pakets hier und in
`target/restart-audit/vpn-kit-created.json` lokal festgehalten:
`594b1dafbc127d5cf188fbad772bcb52ac3f2345d347a87a6dc46b135d57edd8`.
Das ist noch keine externe Vertrauensverankerung. Bei einer späteren Übergabe
muss diese Prüfsumme über einen vertrauenswürdigen separaten Weg verfügbar sein.

**Validierung: 1.370 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert.** Zehn neue Windows-Tests prüfen Paketinhalt, Grenzen,
Veränderungen und die echte Befehlszeilenschnittstelle. Ein zusätzlicher
Unix-Symlink-Test wird durch die Linux-Clippy-Prüfung erfasst, hier aber nicht
ausgeführt. Elf reine PowerShell-Prüfungen mit synthetischen Rechnerdaten
stellen sicher, dass fehlende Fakten oder Ressourcen nicht als ausreichend
gelten und ausreichende Ressourcen keine VM-/Produktfreigabe erzeugen. Dieser
Skripttest ist auch in den Windows-CI-Ablauf aufgenommen; ein entfernter CI-Lauf
wurde in dieser Etappe nicht ausgelöst.

Windows-Build für alle Targets, Workspace-Clippy mit `-D warnings`, Linux-Clippy
für alle CLI-Targets, Format-/Diff-Prüfung und erzeugte Befehlszeilenhilfen sind
grün. Die reale Rechnerinventur ist unter `target/restart-audit/vpn-host-probe.json`
gespeichert; lokale Prüfprotokolle liegen unter `target/restart-audit/vpn-kit-*`.
Keiner der 49 echten VM-Abnahmefälle wurde ausgeführt oder als bestanden erfasst.

**Nächste Etappe:** Bis eine isolierte Testumgebung verfügbar ist, die noch offene
Journal-Wiederherstellung mit externer Vertrauensbasis und die Betriebsverfahren
weiterentwickeln. Sobald ein geeigneter Gast samt freigegebenen Testmitteln
bereitsteht, das Paket dort unabhängig prüfen und die en-US-/de-DE-Abnahme
beginnen. Produktive Tunnel-Durchsetzung bleibt offen; `OPENVPN_NOT_READY` gilt.

[Entwicklungspaket und Rechnerprüfung](OPENVPN_TEST_KIT.md).

## Fortsetzung 2026-09-22 — Geschützte Journalsicherung und externe Vergleichswerte

Die Windows-CLI unterstützt jetzt `journal-backup` und `journal-backup-verify`.
Damit lässt sich die vollständige vorhandene Journalhistorie offline sichern und
unabhängig vom aktuellen Profilspeicher prüfen. Eine Wiederherstellung beschädigter
Live-Journale wird damit noch nicht durchgeführt oder freigegeben.

Die Sicherung verlangt den zuvor separat festgehaltenen Kettenkopf und die Anzahl
der Einträge. Sie öffnet ausschließlich vorhandene feste Journaldateien, hält die
gleichen Schreib-/Löschsperren wie der Dienst und prüft vor Anlage der Zieldatei
die vollständige Historie. Veraltete Erwartungen oder beschädigte Originale führen
zum Abbruch. Alle Segmente werden unverändert einschließlich ihrer Grenzen in eine
neue Datei kopiert. Eine Ausgabe innerhalb des aktiven Profilspeichers, auch über
anders geschriebene Pfade oder Unterverzeichnisse, ist gesperrt, damit ein Archiv
nicht als künftiges Journal oder andere Produktdatei erscheint.

Das Archiv benötigt einen bestehenden vertraulichen administrativen Elternordner.
Dateien werden ausschließlich neu angelegt; die geerbten Rechte werden vor dem
ersten Schreibzugriff geprüft. Bestehende oder teilweise geschriebene Ausgaben
werden nicht überschrieben oder entfernt. Nach Synchronisierung erfolgen ein
SHA-256-Rücklesevergleich und die vollständige semantische Journalprüfung durch
einen duplizierten Dateihandle bei weiterhin exklusiv gehaltener Ausgabedatei.
Der Live-Zustand wird dabei weder geändert noch durch Exportereignisse ergänzt.

Die Archivprüfung verlangt zusätzlich die unabhängig aufbewahrte Archiv-SHA-256.
Sie liest mit Schreib-/Löschsperre und funktioniert auch bei fehlendem oder
beschädigtem Profilspeicher, ohne diesen anzulegen. Dieselbe begrenzte Frame-
Dekodierung und derselbe Journal-Zustandsautomat wie im Dienst prüfen Schema,
Kette, Reihenfolge, Revisionen sowie Konfigurations-/Wartungsübergänge. Ungeklärte
Prozessbeendigung, ausstehende Paket-/Konfigurationswechsel und offene Reparaturen
bleiben im historischen Ergebnis erhalten. `restoration_performed` und
`inspection.accepts_intent` sind für diese Archive immer falsch.

Das Format `SSKJNL01` enthält lediglich Segmentanzahl, Segmentlängen und die
unveränderten Journalbytes. Es enthält keine frei wählbaren Dateinamen oder
Extraktionsoperation. Es gelten weiterhin 64 Segmente mit jeweils 16 MiB und
20.000 Einträgen sowie 4 KiB je Datensatz: maximal 1 GiB plus 524 Hüllbytes.
Die Verarbeitung benötigt begrenzte Puffer statt einer vollständigen Kopie der
Historie im Arbeitsspeicher. Einzelne alte Schema-1-Journale bleiben unverändert
lesbar; mehrere Segmente benötigen weiterhin die Schema-2-Sperrmarkierung im Ursprung.

Die Referenzwerte müssen aus vertrauenswürdiger separater Verwahrung stammen und
dem richtigen Rechner zugeordnet sein. Werden Archiv und Referenz gemeinsam
ersetzt, kann diese Prüfung das nicht erkennen. Eine gültige alte Sicherung beweist
auch nicht den neuesten Maschinenzustand. Ein externer Signier-/Verankerungsdienst,
automatischer Abgleich beim Dienststart, Exportaudit und Retentionsüberwachung
sind noch nicht implementiert. Die Betriebsanleitung benennt die zu verwahrenden
Werte, Verantwortlichkeiten und diese Grenzen ausdrücklich.

Journalarchive enthalten **unverschlüsselte vertrauliche Metadaten**, etwa Benutzer-,
Profil- und Prozesskennungen. Sie enthalten keine Konfigurationsdateien, privaten
Schlüssel oder Management-Geheimnisse. Ihre Schutzschicht sind geprüfte Windows-
Rechte; verschlüsselte Ablage und Übertragung sind separat bereitzustellen. Sie
werden nicht in das öffentliche Entwicklungspaket oder bereinigte Abnahmenachweise
aufgenommen. Die bereits vorhandene verschlüsselte Konfigurationssicherung bleibt
ein eigener, ergänzender Vorgang.

**Validierung:** Der vollständige Windows-Workspace-Lauf besteht mit **1.386 Tests,
0 Fehlern und 1 bestehendem ignorierten Generator**. Enthalten sind 15 neue
Windows-Archivtests und ein neuer CLI-Vertragstest. Anschließend bestehen alle
26 Recorder-/CLI-Tests, einschließlich eines zusätzlich ergänzten Tests für die
Abwärtskompatibilität des Entwicklungspakets. Windows-Build für sämtliche Targets,
Workspace-Clippy mit `-D warnings`, Linux-Clippy für alle CLI-Targets, Format-/Diff-
Prüfung und erzeugte Befehlszeilenhilfen bestehen ebenfalls.

Die Tests prüfen unter anderem entfernte vollständige Historienenden bei neu
berechneter Archivprüfsumme, beschädigte/vertauschte/unvollständige Daten,
gefälschte Grenzen, leere Endsegmente, alte Schema-1-Daten, Originalschutz,
gesperrte Live-Dateien, harte Links und unsichere Rechte vor dem ersten Byte.
Windows-Dateien und Handles sind echt; die ACL-Beobachtungen der neuen Tests
stammen aus privaten Testzugängen. Eine echte VM-, LocalSystem-, Benutzerwechsel-
oder Stromausfallabnahme wird dadurch nicht ersetzt. Kein produktives Journal
wurde für diese Entwicklung exportiert oder verändert.

Neue Entwicklungspakete verwenden Manifest-Schema 2 und enthalten zusätzlich die
Journal-Betriebsanleitung. Der aktuelle Prüfer unterstützt weiterhin Schema 1;
auch das zuvor erzeugte reale Paket wurde erfolgreich gegen seinen alten separat
festgehaltenen Hash geprüft. Das neue geprüfte Paket liegt unter
`target/restart-audit/openvpn-development-kit-2026-09-22-journal/` und enthält
20 Nutzdateien mit insgesamt 27.255.163 Bytes plus Manifest. Es bleibt ein
unsignierter Debug-Build mit `worktree_dirty: true` und `release_ready: false`.
Manifest-SHA-256: `548fe8b1b4f34af79254715ac8bdea00e538eda0ed25aaef7a906475c1f312ab`.
Diese lokale Notiz ist keine externe Vertrauensverankerung.

**Nächste Etappe:** einen wiederaufnehmbaren Journal-Ersatzvorgang mit Startblockade
des Dienstes, Erhalt beschädigter Originale und verlässlicher Bindung an den neuesten
extern belegten Maschinenzustand entwickeln. Ohne diese Voraussetzungen bleibt
direktes Zurückspielen gesperrt. J07/B06 und die echte VM-Abnahme bleiben offen;
produktive Tunnel-Durchsetzung fehlt weiterhin und `OPENVPN_NOT_READY` gilt.

[Journalsicherung und Verwahrung der Referenzwerte](OPENVPN_JOURNAL_BACKUP.md).
Lokale Prüfprotokolle: `target/restart-audit/vpn-journal-archive-*`.

## Fortsetzung 2026-09-22 — Wiederaufnahmefähige Journal-Rekonstruktion in Quarantäne

Die CLI bietet jetzt `journal-diagnose`, `journal-recovery-stage` und
`journal-recovery-resume`. Damit lassen sich beschädigte Journaldateien erfassen,
Originale unverändert bewahren und eine gegen separat verwahrte Referenzwerte
geprüfte Sicherung in einen geschützten Quarantänebereich rekonstruieren. Die
Rekonstruktion aktiviert den Stand noch nicht für den laufenden VPN-Betrieb.

Die Diagnose liest die vorhandenen kanonischen Segmentdateien mit denselben
Schreib-/Löschsperren wie der Dienst, aber ohne beschädigte Datensätze interpretieren
zu müssen. Sie liefert Indizes, Größen, SHA-256-Werte und einen Digest über den
gesamten beobachteten Satz. Lücken, ein fehlender Ursprung und ein leerer Satz
werden ausdrücklich erfasst. Unsichere Rechte, harte Links, Reparse-Pfade,
unzulässige Namen und überschrittene Grenzen bleiben Fehler. Es werden keine
fehlenden Journaldateien angelegt und keine beschädigten Inhalte ausgegeben.

Vor der Rekonstruktion müssen Archiv-SHA-256, Kettenkopf, Eintragszahl und der
Digest aus der Diagnose übereinstimmen. Das vollständige Archiv wird mit der
bestehenden Journalprüfung validiert; leere Archivhistorie ist als Kandidat
ausgeschlossen. Danach wird ein unveränderlicher, synchronisierter Plan unter
`openvpn-control-recovery.journal` neu angelegt und exklusiv gehalten. Dieser
reservierte Name sperrt sämtliche normalen Journalöffnungen, auch in älteren
segmentierten Lesern. Selbst ein leerer oder unvollständiger Marker verhindert,
dass ein fehlender Ursprung als neue Historie angelegt wird.

Die Sperre betrifft die Initialisierung der VPN-Steuerdomäne. Der übergeordnete
Windows-Dienst kann weiterhin Diagnose und unabhängige andere Steuerdomänen
bereitstellen. Die Befehle starten oder stoppen den Dienst nicht automatisch.
Noch ältere unsegmentierte Programme und Binär-Downgrades sind während einer
Wiederherstellung nicht unterstützt.

Jeder Versuch erhält unter `journal-recovery-<id>/attempt-<nummer>/` getrennte
Verzeichnisse für unveränderte Originalnachweise und rekonstruierte Kandidaten.
Es werden ausschließlich feste Journalnamen verwendet. Jeder Zielhandle wird vor
dem ersten Byte auf vertrauliche Rechte geprüft, jede Datei neu angelegt und
synchronisiert. Originalnachweise müssen den diagnostizierten Satz exakt ergeben;
der Kandidat muss auch einschließlich Segmentgrenzen die ursprüngliche Archiv-
SHA-256, den Kettenkopf und die Eintragszahl reproduzieren. Die vollständige
semantische Journalprüfung läuft erneut. Geöffnete Nachweis-/Kandidatendateien
bleiben gesperrt, bis der Abschlussdatensatz geschrieben und rückgelesen ist.

Nach einem Abbruch verlangt `journal-recovery-resume` alle ursprünglichen
Vergleichswerte und zusätzlich die separat festgehaltene Planprüfsumme. Ein
vollständiger Versuch wird erneut geprüft und unverändert zurückgegeben. Ein
unvollständiger Versuch bleibt erhalten; ein neuer Versuch erhält ein eigenes
Verzeichnis. Beschädigte Kopien werden nicht überschrieben. Die Grenze liegt bei
vier Versuchen und damit höchstens 8 GiB Kopierdaten plus kleinen Metadaten,
zusätzlich zu Originalen und Quellarchiv. Veränderte abgeschlossene Nachweise,
unlesbare Pläne, geänderte Originale oder ausgeschöpfte Versuche bleiben gesperrt.
Es gibt weder erzwungene Fortsetzung noch automatische Bereinigung oder Freigabe.

Die Betriebsanleitung erklärt das Verhalten nach einem unsicheren Aufrufergebnis,
die getrennte Verwahrung der Referenzwerte, den Schutz und Speicherbedarf der
Nachweise und den Umgang mit Teilversuchen. Der Marker darf nicht manuell gelöscht
werden: Damit würde der ursprüngliche Journalpfad wieder zugänglich und die
Wiederherstellungssperre umgangen. `activation_performed` bleibt stets falsch;
ungeklärte Prozesszustände und ausstehende Konfigurations-/Wartungsvorgänge werden
im historischen Ergebnis erhalten. Die Referenzwerte müssen weiterhin aus
vertrauenswürdiger, dem richtigen Rechner zugeordneter Verwahrung stammen.

**Validierung: 1.401 Workspace-Tests bestanden, 0 fehlgeschlagen und 1 bestehender
Generator ignoriert.** Neu sind 13 Windows-Wiederherstellungstests und ein
CLI-Vertragstest. Die Tests unterbrechen nach synchronisiertem Marker, Original-
kopie, Kandidatenkopie und Abschluss; sie prüfen Wiederaufnahme, fehlende Ursprünge,
geänderte abgeschlossene Nachweise, veraltete Erwartungen, unsichere Rechte vor dem
ersten Byte, begrenzte Versuche und unveränderte beschädigte Originale. Ein
absichtlich beschädigter Kopierstand erhält keinen Abschlussnachweis. Reale
Windows-Dateien und Handles werden verwendet; ACL-Beobachtungen sind private
Testzugänge. Die echte VM-/LocalSystem-/Stromausfallabnahme bleibt offen.

Windows-Build für alle Targets, Workspace-Clippy mit `-D warnings`, Linux-Clippy
für alle CLI-Targets, Format-/Diff-Prüfung und Befehlszeilenhilfen bestehen.
Die 17 Workspace-Abhängigkeiten des Daemons bleiben unverändert. Die neue
Wiederherstellung wurde ausschließlich mit temporären Testdaten ausgeführt;
am produktiven Profilspeicher wurde kein Marker oder Quarantänebereich angelegt.

Das neu erzeugte und geprüfte Entwicklungspaket liegt unter
`target/restart-audit/openvpn-development-kit-2026-09-22-recovery/`. Es enthält
20 Nutzdateien mit insgesamt 26.719.594 Bytes plus Manifest, einschließlich der
erweiterten Betriebsanleitung. Es bleibt ein unsignierter Debug-Build mit
`worktree_dirty: true` und `release_ready: false`. Manifest-SHA-256:
`b8f572d28c80008545fd510e691ca84f4b178064b242bdad986f856e73134592`.
Diese lokal festgehaltene Prüfsumme ist noch keine externe Vertrauensverankerung.

**Nächste Etappe:** die kontrollierte Aktivierung eines vollständig geprüften
Quarantänestands entwickeln, einschließlich verlässlicher Bindung an den neuesten
extern belegten Maschinenzustand, Prüfung zugehöriger Konfigurations-/Paketstände
und frischer OS-Nachweise für alte Prozessidentitäten. Bis dahin bleibt die
VPN-Steuerdomäne nach einer Rekonstruktion gesperrt. J07/B06 bleiben offen;
produktive Tunnel-Durchsetzung fehlt weiterhin und `OPENVPN_NOT_READY` gilt.

[Quarantäneablauf und Betriebsgrenzen](OPENVPN_JOURNAL_BACKUP.md#reconstruct-in-blocked-quarantine).
Lokale Prüfprotokolle: `target/restart-audit/vpn-journal-recovery-*`.

## 2026-09-22: Offline-Analyse als erster Membran-Baustein

Auf die [Membran-Recherche](NETWORK_MEMBRANE_RESEARCH_2026-09-22.md) und die
[Prüfung von Thronion](THRONION_MEMBRANE_ASSESSMENT_2026-09-22.md) folgt jetzt
`ssk-netanalysis`. Es übernimmt die Trennung von Beobachtung und Auswertung als
Architekturidee; Thronion-Code oder dessen Klassifikator werden nicht eingebunden.

Die neue Bibliothek und das separate Werkzeug `ssk-netanalysis-replay` werten
gespeicherte Beobachtungen für genau einen Scope und ein Zeitfenster aus. Vier
nachvollziehbare Kriterien prüfen Verbindungsrate, Fehlerquote, gesendete Datenrate
und das Verhältnis gesendeter zu empfangenen Bytes. Ganzzahlige Vergleiche ersetzen
einen unkalibrierten Gesamtscore. Die konfigurierten Parameter sind unveränderlich
und durch eine Versionskennung gebunden; ihre Beispielwerte sind noch nicht anhand
realer Verkehrsdaten kalibriert.

Verlust, Sequenz-/Zeitfehler, Scope-Wechsel, Überläufe, ausgeschöpfte Grenzen,
unvollständige Fenster und abgelaufene Bewertungen ergeben ausdrücklich
`unavailable`. Der erste Fensterfehler bleibt bestehen. Ein unauffälliger Bericht
ist weder eine Aussage „schadfrei“ noch eine Verbindungsfreigabe. Herkunft,
Prozessidentität und vollständige Erfassung sind weiterhin unbestätigt; jeder
Bericht kennzeichnet dies ausdrücklich. Fensterabschluss und nachträgliche
Korrekturen benötigen vor einem Live-Einsatz einen belastbaren Quellenvertrag.

Die Komponente hat keine Netzwerk-, Broker- oder WFP-Funktionen. Keine bestehende
Produktkomponente bindet sie ein. Der Dependency-Test untersagt ihre unbeabsichtigte
Aufnahme in den Daemon zusätzlich ausdrücklich; dessen 17 Workspace-Abhängigkeiten
bleiben unverändert. Der begrenzte JSON-Leser akzeptiert höchstens 1 MiB und 4.096
Ereignisse; der eigentliche Fensteranalysator bewahrt nur Zähler auf.

**Validierung: 1.430 Workspace-Tests bestanden, 0 fehlgeschlagen und 1 bestehender
Generator ignoriert.** Darin enthalten sind 29 neue Prüfungen für Grenzen,
Fehlerzustände, Bindung/Gültigkeit, Parser und das ausführbare Replay-Werkzeug.
Es wurde kein Live-Verkehr erfasst und keine Firewall-, VPN- oder Dienstkonfiguration
verändert. Eine Schutzwirkung auf dem Rechner wird damit noch nicht bereitgestellt.

Windows-Build und Workspace-Clippy für alle Targets mit `-D warnings`, Linux-Clippy
für alle Targets der neuen Komponente und Format-/Diff-Prüfung bestehen. Linux-Tests
wurden hier nicht ausgeführt. Das synthetische Beispiel liefert mit dem gebauten
Replay-Werkzeug die vier erwarteten Kriterien und weist seine fehlende Durchsetzung
ausdrücklich aus. Bestehende Registry-Abhängigkeiten wurden nicht aktualisiert.

**Nächste Etappe der Membran:** den Vertrag einer echten Windows-Beobachtungsquelle
für Prozessinkarnation, Zeitbasis, Vollständigkeit, Verluste und abgeschlossene
Fenster ausarbeiten. Anschließend echte Aufzeichnungen im Beobachtungsmodus
auswerten und Fehlalarme messen. Die PolicyEngine bleibt die zuständige Instanz;
WFP-Durchsetzung, isolierte Windows-Abnahme und die zuvor beschriebene kontrollierte
VPN-Journalaktivierung bleiben offene eigenständige Arbeiten. `OPENVPN_NOT_READY`
gilt weiterhin.

[Bedienung und Grenzen der Analyse](NETWORK_ANALYSIS_BASELINE.md).
Lokale Prüfprotokolle: `target/restart-audit/netanalysis-*`.

## 2026-09-22: Begrenzte Windows-Diagnose für die Membran

`ssk-winhost::network_snapshot` und das separate Werkzeug `ssk-netobserve`
lesen jetzt TCP-/UDP-Endpunkte über IPv4 und IPv6 für eine ausgewählte PID.
Vor den Tabellen wird der Prozess mit ausschließlich Abfrage-/Synchronisierungs-
rechten geöffnet. Derselbe Handle muss vor und nach der Aufnahme einen lebenden
Prozess bezeichnen; Prozessende verwirft den gesamten Bericht. Die Erstellungszeit
bleibt als exakte dezimale FILETIME-Zeichenkette erhalten. Die PID wird zum
Abfragezeitpunkt aufgelöst, nicht rückwirkend einem historischen Ereignis zugeordnet.

Jede Tabelle zeigt Erfolg oder einen konkreten Fehler. Größenabfrage und Wiederholungen
sind auf vier OS-Aufrufe begrenzt, Rohdaten auf 1 MiB, geprüfte Tabellenzeilen auf
16.384 und passende Ergebniszeilen auf 1.024 je Tabelle. Unvollständige Tabellen
und überschrittene Grenzen ergeben keinen erfolgreichen Präfix. Das Gesamtbudget
beträgt zwei Sekunden und wird zwischen synchronen OS-Aufrufen geprüft; einen im
OS hängenden Aufruf kann es noch nicht unterbrechen.

Die neue Diagnose hat einen eigenen strengen Parser und übernimmt nicht die
tolerante IPv4-/HTTP-ähnliche Abbildung der älteren Capture-Schnittstelle. TCP-Zustände
bleiben rohe MIB-Werte; UDP und TCP-LISTEN erhalten keine erfundene Gegenstelle.
Weder Byte-Messwerte noch vollständige Verbindungsereignisse oder Verlustzähler
werden vorgetäuscht. `baseline_compatible` und `enforcement_active` bleiben falsch.
Die Verhaltensanalyse kann diese Diagnoseberichte nicht als Eingaben übernehmen.
Daemon und Broker rufen die neue Diagnose nicht auf.

**Validierung: 1.450 Workspace-Tests bestanden, 0 fehlgeschlagen und 1 bestehender
Generator ignoriert.** Neu sind 20 Prüfungen, darunter echte Windows-Abfragen von
eigenen IPv4-/IPv6-Loopback-Sockets und ein ausgeführter CLI-Bericht. Die gezielte
Fehlerinjektion prüft Prozessende und Tabellenfehler; tatsächlich erzwungenes
PID-Recycling wurde nicht getestet. Der direkte Selbsttest las alle vier Tabellen;
das Analyse-Replay wies seinen Bericht mit dem erwarteten Exitcode 2 ab.

Windows-Build und Workspace-Clippy für alle Targets mit `-D warnings`, Linux-Clippy
für alle `ssk-winhost`-Targets, Format-/Diff-Prüfung und lokale Dokumentationslinks
bestehen. Linux-Tests wurden hier nicht ausgeführt. Keine neuen Abhängigkeiten;
die 17 Workspace-Abhängigkeiten des Daemons bleiben erhalten. Es wurden keine
Firewallregeln, VPN- oder Dienstkonfigurationen verändert.

**Nächste Etappe:** geeignete Netzwerk- und Prozessereignisquellen auf Windows
gegen den dokumentierten Vertrag prüfen: sichere zeitliche Prozesszuordnung,
Merkmalssemantik, Verlustmeldungen, begrenzte Warteschlangen und nachvollziehbarer
Fensterabschluss. ETW ist ein Kandidat, aber noch nicht implementiert. WFP und
isolierte Abnahme bleiben offen; `OPENVPN_NOT_READY` gilt unverändert.

[Diagnose bedienen und Quellenvertrag](WINDOWS_NETWORK_OBSERVATION.md).
Lokale Prüfprotokolle: `target/restart-audit/network-source-*`.

## 2026-09-22: ETW-Decoder mit expliziter Verlustprüfung

Die Quellenprüfung identifiziert die klassischen TcpIp-/UdpIp-Kernel-Provider als
Kandidaten für Ereignisdiagnose. Zwei wesentliche Grenzen sind jetzt in Code und
Dokumentation festgehalten: Die Header-PID kann vom Urheber der Netzwerkaktivität
abweichen; die Payload-PID muss verwendet werden. Die Fail-Ereignisse enthalten
hingegen keine PID/Endpunkte und ergeben keine anwendungsbezogene Fehlerquote.
Außerdem ist `EVENT_TRACE_LOGFILEW.EventsLost` unbenutzt und darf nicht als
Verlustfreiheitsnachweis dienen. Ein späterer Controller muss tatsächliche
Sitzungsstatistiken und eigene Queue-Verluste erfassen.

`ssk-winhost::network_etw` und `ssk-netobserve etw-replay` verarbeiten jetzt
synthetische oder unbestätigte JSON-Exporte. Windows TDH löst feste Eigenschaftsnamen
für die explizit zugelassenen Version-2-Ereignisse auf; Eigenschaftsgrößen und
Headerformate werden geprüft. Es gibt keinen Rückfall auf geratene Bytepositionen.
Der native Aufruf verwendet ausschließlich eigenen, begrenzten Speicher.
Unbekannte Schemas oder Metadatenfehler bleiben sichtbar nicht auswertbar.

Fehlende/gestiegene Verlustzähler, Zählerrücksetzung, fehlender Abschluss, unerwartete
Datensatzanzahl, Lücken in Export-Ordinals und Zeitfehler werden abgewiesen. Der
erste Ereignisfehler beendet die Verarbeitung; bereits dekodierte Zähler sind nur
ein ausdrücklich markierter Präfix. TCP-Senden, Empfang, Retransmit, TCPCopy,
Connect/Reconnect und nicht zugeordnete Fail-Ereignisse bleiben getrennt.

Die Eingabegrenzen liegen bei 1 MiB, 512 Datensätzen, 256 Payload-Bytes je Ereignis
und höchstens 60 Sekunden deklarierter Dauer. Ein fünfsekündiges Decodierbudget
wird zwischen Datensätzen geprüft; einen im OS hängenden TDH-Aufruf kann es nicht
unterbrechen. Der spätere Dienst braucht deshalb einen beaufsichtigten Worker.
Die Diagnose enthält keine Anwendungsidentitäts-, Vollständigkeits- oder
Durchsetzungsgarantie. `baseline_compatible` und `enforcement_active` bleiben falsch.

**Validierung: 1.478 Workspace-Tests bestanden, 0 fehlgeschlagen und 1 bestehender
Generator ignoriert.** Neu sind 28 Prüfungen, einschließlich echter TDH-Auflösung
synthetischer Ereignisse mit allen zugelassenen Opcodes, IPv4/IPv6 und 32-/64-Bit-
Pointerbreiten. Nach einem Metadatenfehler in der eingeschränkten Sandbox gelang
die lesende native Prüfung außerhalb dieser Sandbox. Es wurden keine Rechte oder
WMI-Einstellungen verändert. Das gebaute CLI lieferte den erwarteten Beispielbericht;
die Verhaltensanalyse wies ihn als ungeeignete Eingabe mit Exitcode 2 ab.

Windows-Build und Workspace-Clippy für alle Targets, Linux-Clippy für alle
`ssk-winhost`-Targets, Format-/Diff- und lokale Linkprüfung bestehen. Linux-Tests
wurden hier nicht ausgeführt. Lediglich das ETW-Feature der vorhandenen
`windows-sys`-Version wurde aktiviert; der Daemon behält 17 Workspace-Abhängigkeiten.
Es wurde keine ETW-Sitzung gestartet, kein Live-Ereignis empfangen und keine
Firewall-, VPN- oder Dienstkonfiguration verändert.

**Nächste Etappe:** eine echte, zunächst lesende ETL-Quelle mit kontrollierter
Worker-Lebensdauer und anschließend zeitlicher Prozessstart/-ende-Zuordnung
anbinden. Reale Aufzeichnungen müssen die lokal auflösbaren Schemas, Byte-Semantik,
Offloading und Fensterabschluss bestätigen. WFP und isolierte Windows-Abnahme
bleiben offen; `OPENVPN_NOT_READY` gilt unverändert.

[Quellenbefunde, Decoder und Bedienung](ETW_NETWORK_DECODER.md).
Lokale Prüfprotokolle: `target/restart-audit/etw-decoder-*`.

## 2026-09-22: Überwachter ETL-Dateileser

`ssk-netobserve etl <recording.etl>` liest jetzt vorhandene lokale ETL-Dateien
über Windows `OpenTraceW`/`ProcessTrace`. Der native Dateileser und seine TDH-Aufrufe
laufen in einem eigenen Prozess: atomare Job-Zuordnung, Kill-on-close,
Prozesslimit 1, 256 MiB Commit-Limit und eine vom Elternprozess überwachte
10-Sekunden-Deadline. Der Elternprozess liest die anonyme Ergebnispipeline ohne
unbegrenzten Read und weist mehr als 16 KiB oder ungültige Nachrichten ab.
Die vorbereitenden Datei-/Prozessstartaufrufe bleiben synchrone OS-Aufrufe;
der Worker läuft unter demselben Benutzer und ist keine Sicherheits-Sandbox.

Die Eingabe ist auf 64 MiB begrenzt, während des Lesens gegen Schreiben/Löschen
gepinnt und über den endgültigen Handle-Pfad aufgelöst. Höchstens 100.000 Callbacks
und 10.000 ausgewählte Netzwerkereignisse werden verarbeitet. TDH erhält den
ursprünglichen nativen Callback-Datensatz. Unbekannte Netzwerkformate, nicht
unterstützte Zusatzdaten, Zeitregression oder Limits beenden die Auswertung.
Der erste Fehler bleibt erhalten; bereits dekodierte Zähler sind nur ein Präfix.

Verlust-/Abschlussangaben werden aus dem tatsächlichen Dateikopf gelesen.
Unfinalisierte, verlustbehaftete, zirkuläre, angehängte oder aufgeteilte Dateien
werden abgewiesen. Ein klassischer LostEvent-Marker führt ebenfalls zum Abbruch.
Nullwerte sind weiterhin kein Nachweis vollständiger Erfassung. Der separate
ETL-Bericht behauptet weder Datei-Authentizität noch historische Prozessidentität
oder Verkehrsabdeckung und kann nicht als Baseline-Eingabe verwendet werden.

**Validierung: 1.498 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 146 Testsuiten.** Neu sind 20 Prüfungen. Ein wirklich hängender
Testprozess wird durch die Überwachung beendet; weitere Tests prüfen Ausgabeüberlauf,
Absturz, Handle-Sperren, Job-Limits, Callback-/Protokollfehler und native TDH-Auflösung.
Ein Integrationstest erzeugt und schließt eine kleine echte ETL-Datei ausschließlich
mit einem privaten In-Process-Testprovider. Das gebaute CLI durchläuft diese Datei
im begrenzten Worker und meldet korrekt fehlende unterstützte Netzwerkereignisse.
Es wurden keine Kernel-/Netzwerkprovider und keine systemweite Aufzeichnung aktiviert.

Windows-Workspace-Build und Clippy für alle Targets, Linux-Clippy für alle
`ssk-winhost`-Targets, Format-/Diff- und lokale Dokumentationslinkprüfung bestehen.
Linux-Tests wurden hier nicht ausgeführt. Die vorhandenen VPN-Jobprüfungen bestehen
ebenfalls; der ursprüngliche Startpfad ohne Handle-Vererbung bleibt erhalten.
Keine neuen Registry-Abhängigkeiten; nur das `Win32_System_Time`-Feature wurde
ergänzt. Der Daemon behält seine 17 Workspace-Abhängigkeiten.

**Nächste Etappe:** historische Prozessstart/-ende-/Rundown-Zuordnung mit
PID-Wiederverwendung und sichtbaren Quelllücken. Die komplette Kette mit echten
Kernel-Netzwerkereignissen, Offloading und kontrollierten Verlusten ist weiterhin
in einer isolierten Windows-Umgebung abzunehmen. Diese steht noch nicht bereit.
WFP-Durchsetzung bleibt offen und `OPENVPN_NOT_READY` gilt weiterhin. Firewall-,
Routing-, VPN- und Dienstkonfiguration wurden nicht verändert.

[Bedienung, Grenzen und Abnahmenachweise](ETL_NETWORK_READER.md).
Lokale Prüfprotokolle: `target/restart-audit/etl-*`.

## 2026-09-22: Zeitliche Prozesszuordnung mit später Invalidierung

Der ETL-Dateileser dekodiert nun zusätzlich klassische Prozessereignisse der
Versionen 2, 3 und 4 mit den Start-/End-/DCStart-/DCEnd-Opcodes. Native TDH-Abfragen
lesen ausschließlich Payload-`ProcessId` und `UniqueProcessKey` mit geprüften
Größen. Die Prozessschlüssel bleiben als nicht dauerhafte Kernel-Objekthinweise
innerhalb des Workers. Namen, SIDs und Kommandozeilen werden nicht abgefragt oder
ausgegeben; aktuelle Prozesse werden nicht zur historischen Identifikation geöffnet.
Die unterstützten Schemas wurden lesend mit dem lokalen WMI-Bestand abgeglichen.

Eine begrenzte Historie trennt pro PID beobachtete Lebenszeiten. Ein Ende und ein
späterer Start erzeugen getrennte Lebenszeiten, selbst bei derselben Objektadresse.
Bestandsereignisse bestätigen Existenz ab ihrem eigenen Zeitstempel und werden
weder zurückdatiert noch als Erstellungs- oder Beendigungsereignis ausgegeben.
Netzwerkdaten müssen strikt zwischen einer unteren und einer späteren passenden
Prozessbeobachtung liegen. Ein Dateiende allein schließt keine Prozesslebenszeit.
Gleiche Grenzzeitstempel bleiben unabhängig von der Callback-Reihenfolge mehrdeutig.

Erst nach vollständigem Dateidurchlauf und CloseTrace werden die Korrelationszähler
berechnet. Späte Verlustmeldungen, Widersprüche, Zeitregression oder Quellenfehler
verwerfen sämtliche Zuordnungen des Durchlaufs. Fehlende Startdaten, nicht
geschlossene Beobachtungsfenster, Ereignisse außerhalb der Intervalle und Fehler
ohne Payload-PID bleiben gesondert sichtbar. Bestehende Netzwerkzähler werden
weiterhin nur als Diagnose ausgegeben. Alle Vertrauens-/Berechtigungsfelder bleiben
falsch; eine importierte Datei liefert weiterhin keine beglaubigte Prozessidentität.

Der ETL-Bericht verwendet jetzt Schema-Version 2 mit `process_correlation` und
Prozessereigniszählern. Neue Grenzen: 10.000 Prozessprovider-Ereignisse,
4.096 Lebenszeiten und 8 KiB Prozesspayload. Historien werden bei Erreichen der
Grenzen nicht verdrängt. Die bisherigen Worker-/Datei-/Netzwerkgrenzen bleiben
erhalten; der interne Berichtsparser prüft die neuen Zähler und weist zusätzliche
Berechtigungsfelder ab.

Die neue parallele TDH-Prüfung deckte lokal widersprüchliche Pointer-Eigenschaftsgrößen
bei gleichzeitigem 32-/64-Bit-Decodieren auf. Expliziter `TDH_CONTEXT_POINTERSIZE`
allein genügte nicht. Alle nativen Netzwerk- und Prozessdecoder teilen sich jetzt
eine prozessweite Sperre für die vollständige Datensatzdekodierung. Die Größenprüfung
bleibt unverändert strikt; eine vergiftete Sperre wird als Fehler gemeldet. Die
66 ETW-Modulprüfungen einschließlich des parallelen Regressionsfalls bestehen.

**Weitere Arbeit:** überprüfbarer Quellenabschluss mit Provider-/Verlustnachweisen
und ein reproduzierbares Abnahmeszenario. Echte kombinierte Kernel-Netzwerk- und
Prozessaufzeichnungen, tatsächliches PID-Recycling und real erzeugte Verluste
müssen in einer isolierten Windows-Umgebung geprüft werden; diese steht noch
nicht bereit. Verhaltensanalyse und Durchsetzung bleiben abgekoppelt. Es wurden
keine Kernel-/Netzwerkaufzeichnungen gestartet und keine Firewall-, Routing-,
VPN- oder Dienstkonfigurationen geändert. `OPENVPN_NOT_READY` gilt weiterhin.

[Berichtsvertrag, Zuordnungsregeln und Grenzen](ETL_PROCESS_CORRELATION.md).
Lokale Prüfprotokolle: `target/restart-audit/process-correlation-*`.

**Abschließende Validierung: 1.524 Workspace-Tests bestanden, 0 fehlgeschlagen,
1 bestehender Generator ignoriert; 146 Testsuiten.** Dieser Schritt ergänzt
26 Modulprüfungen und erweitert die vorhandene ETL-CLI-Abnahme auf Schema-Version 2.
Windows-Workspace-Build und Clippy für alle Targets, Linux-Clippy für alle
`ssk-winhost`-Targets sowie Format-/Diff- und lokale Linkprüfung bestehen.
Linux-Tests wurden hier nicht ausgeführt. Keine zusätzlichen Abhängigkeiten;
die 17 Workspace-Abhängigkeiten des Daemons bleiben unverändert.

## Fortsetzung: Konsistenzprüfung des Aufzeichnungsabschlusses

`ssk-netobserve etl-check <recording.etl> <closure.json>` ergänzt einen streng
begrenzten Importvertrag für Controller-Abschlussangaben. Der Elternprozess
berechnet SHA-256 aus dem gehaltenen ETL-Dateihandle und prüft Länge, deklarierte
Quellenkonfiguration, Sitzungszugehörigkeit der Momentaufnahmen, erfolgreiche
Start-/Abfrage-/Stoppangaben und kumulative Verlustzähler. Fehlende Angaben,
Verluste, rückläufige Zähler, Abweichungen vom versionierten Prozess-/Netzwerkprofil
und Fehler der ETL-Auswertung verhindern ein konsistentes Ergebnis.

Der neue Gesamtbericht verwendet Schema 1; der enthaltene ETL-Bericht bleibt
Schema 2. `consistent_unverified` bestätigt ausschließlich Konsistenz unbestätigter
Eingaben. Eine Prüfsumme oder selbst erklärte Kontinuität beglaubigen weder den
Aufzeichner noch vollständige Providerabdeckung. Alle Vertrauens-, Analyse- und
Durchsetzungsfelder bleiben falsch. JSON-Eingaben sind auf 16 KiB begrenzt und
werden ebenso wie die ETL-Datei ohne Schreib-/Löschfreigabe geöffnet. Hashen und
Dateivorbereitung liegen außerhalb der bestehenden Worker-Deadline.

Die native Testdatei enthält jetzt echte `ControlTraceW(QUERY/STOP)`-Statistiken
eines ausschließlich privaten Testloggers im eigenen Prozess. Trotz passendem
Hash und Nullverlusten wird sie korrekt als ungeeignet für das Systemprofil und
ohne Netzwerkereignisse bewertet. Es wurden keine Kernel-/Netzwerkprovider
aktiviert und keine Firewall-, VPN-, Routing- oder Dienstkonfigurationen geändert.

**Validierung: 1.543 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 146 Testsuiten.** 16 neue Modulprüfungen und drei neue
CLI-Tests; die sieben ETL-CLI-Tests bestehen auch nach der abschließenden Ergänzung
der Schreibsperrenprüfung. Windows-Workspace-Build und Clippy für alle Targets,
Linux-Clippy für alle `ssk-winhost`-Targets sowie Format-/Diff- und lokale
Linkprüfung bestehen. Keine neuen Abhängigkeiten; Daemon-Abhängigkeitsprüfung
unverändert grün. Linux-Laufzeittests wurden hier nicht ausgeführt.

**Nächster Schritt:** einen begrenzten eigenen System-Trace-Controller und eine
deterministische lokale TCP-/UDP-Testlast implementieren, zunächst für die noch
fehlende isolierte Windows-Testumgebung. Die dokumentierte VM-Abnahme muss
echte kombinierte Kernel-/Prozessereignisse, Verluste, Provideränderungen und
PID-Recycling belegen. Die Herkunft des Imports bleibt derzeit unbeglaubigt.
Aktive Membran-/WFP-Durchsetzung und OpenVPN-Bereitschaft bleiben offen;
`OPENVPN_NOT_READY` gilt weiterhin.

[Vertrag und reproduzierbare Abnahme](ETL_RECORDING_CLOSURE.md).
Prüfprotokolle: `target/restart-audit/etl-closure-*`.

## Fortsetzung: privater Aufzeichnerkern und Loopback-Testlast

Der separate Befehl `ssk-netcapture` bietet `plan`, `private-fixture <new-directory>`
und `traffic`. Der interne Controller besitzt ausschließlich selbst erfolgreich
gestartete Sitzungen, prüft Aktivierung, Zwischenstatistiken, Verluste und Zeit,
und beendet seine private Sitzung auch bei Fehlern. Ein Drop-Guard ergänzt die
normale Stoppfolge bei Rust-Unwinding; unklare Stoppfehler werden einmal erneut
versucht, ohne die ursprüngliche Störung aus dem Bericht zu löschen. Die nativen
Aufrufe sind synchron und nicht präemptiv begrenzt.

Die native Umsetzung ist auf private Ereignisse im eigenen Prozess festgelegt:
acht synthetische Ereignisse, 1-MiB-Dateigrenze, kooperatives Ein-Sekunden-Budget.
Ein neues Verzeichnis enthält ETL, Controllerprotokoll und den zum Dateihash
passenden Abschlussbericht. Bestehende Verzeichnisse/Artefakte werden nicht
wiederverwendet. Die bisherigen ETL-Abnahmetests verwenden jetzt diesen Controller
anstelle einer separaten nativen Testimplementierung. Controller und Abschluss-
prüfer teilen sich dieselben strikten Statistiktypen.

`traffic` erzeugt feste Anfrage-/Antwortpaare auf IPv4-/IPv6-Loopback für TCP und
UDP: acht Nachrichten à 128 Bytes je Fall, mit beidseitiger Inhaltsprüfung.
Es gibt keine externen Ziele, DNS-Auflösung oder frei konfigurierbaren Endpunkte.
Zähler beschreiben ausschließlich abgeschlossene Anwendungsvorgänge; fehlendes
IPv6 oder Fehler bleiben sichtbar. Vier erfolgreiche Fälle ergeben 8.192
verifizierte Anwendungsbytes, keinen ETW-Abdeckungsbeweis.

**Die Systemaufnahme ist noch nicht startbar.** System-Logger können den Tod ihres
Aufzeichnerprozesses überleben. Deshalb liefert `plan` nur die vorgesehene
Konfiguration und nennt Absturzüberwachung, geschützte Ausgabe/Wiederherstellung
und isolierte Windows-Abnahme als fehlende Voraussetzungen. Der private
Drop-Guard ist kein Ersatz dafür. Auch die aktuelle Ausgabeordnerprüfung ist
kein gegen einen feindlich veränderbaren Dateisystem-Namensraum gehärteter
Speicher für sensible Systemaufzeichnungen.

**Validierung: 1.562 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 148 Testsuiten.** 14 neue Controller-Fehlerfalltests, zwei
Testlast-Modulprüfungen und drei neue CLI-Abnahmen. Windows-Workspace-Build und
Clippy für alle Targets, Linux-Clippy für alle `ssk-winhost`-Targets sowie
Format-/Diff- und lokale Linkprüfung bestehen. Linux-Laufzeittests wurden nicht
ausgeführt. Keine neuen Abhängigkeiten; Daemon-Abhängigkeitsprüfung bleibt grün.

Ein zusätzlicher Beispiel-Durchlauf liegt unter
`target/restart-audit/private-capture-acceptance-2026-09-22/`: 131.072 Byte private
ETL-Datei, passende Hashbindung, vollständig erfolgreiche Loopback-Testlast.
`etl-check` weist die Datei erwartungsgemäß mit
`unsupported_profile_configuration` und `etl_unavailable` als ungeeignet für die
System-Netzwerkabnahme aus. Es wurden keine Kernel-/Netzwerkprovider aktiviert und
keine Firewall-, Routing-, VPN- oder Dienstkonfigurationen geändert.

**Nächster Schritt:** prozessübergreifende Lebensdauerüberwachung und sichere
Besitz-/Ausgaberegeln für den künftigen System-Aufzeichner. Reale Kernel-Abnahme,
Bestandsprozess-Testlast, PID-Recycling und tatsächliche Verluste bleiben offen.
`OPENVPN_NOT_READY` und die fehlende aktive WFP-Durchsetzung gelten weiterhin.

[Bedienung, Grenzen und Abnahme](ETW_CAPTURE_PREPARATION.md).
Prüfprotokolle: `target/restart-audit/capture-controller-*`.

## Fortsetzung: überwachte private Erfassung und belegte Bereinigung

`private-fixture` führt die native Aufnahme jetzt in einem eigenen Hilfsprozess
aus. Dieser wird beim Start atomar einem Windows-Job zugeordnet: fünf Sekunden
überwachte Laufzeit, 256 MiB privater zugesicherter Speicher, maximal ein Prozess
und 4 KiB Abschlussnachricht. Bei Abbruch beobachtet der Elternprozess höchstens
eine weitere Sekunde das Prozessende. Job-Schließung beendet den Worker auch
beim Tod des Elternprozesses. Die vorhandene ETL-Auswertung nutzt denselben
Überwachungskern mit ihren bisherigen zehn Sekunden / 16 KiB.

Der Elternprozess schreibt `supervision.json` (Schema 1). Abbruchanforderung,
API-Rücklauf und beobachtetes Prozessende sind getrennte Angaben. Ein Prozessende
beweist keinen sauberen ETW-Abschluss; `session_cleanup_verified` bleibt falsch.
Ungültige Worker-Nachrichten, fehlende/unzulässige Artefakte, Zeitüberschreitungen
und Abstürze werden nicht als erfolgreiche Aufnahme ausgegeben. Nach dem Tod des
Elternprozesses kann der Bericht fehlen; auch das ist kein Erfolgsbeleg.
Fixture- und Planbericht verwenden jetzt Schema 2.

Vor jedem Sitzungsstopp wird die GUID über das gehaltene Handle erneut geprüft.
Fremde oder unbekannte Identität verhindert den Stopp. Der Controllerbericht
(Schema 2) enthält diese Abfrage, den Bereinigungsstatus und gegebenenfalls genau
einen protokollierten weiteren Versuch. Ein unterbliebener Stopp ist `null`.
Der erste Fehler bleibt erhalten. Abfrage und Stopp sind keine atomare Operation;
daraus folgt keine sichere Wiederherstellung systemweiter Sitzungen.

**Validierung: 1.577 Workspace-Tests bestanden, 0 fehlgeschlagen, 1 bestehender
Generator ignoriert; 148 Testsuiten.** Die 112 ETW-Modulprüfungen und elf betroffenen
CLI-Tests bestehen zusätzlich gezielt. Native Fehlerfälle prüfen einen bereits
aktiven privaten Logger bei Hängen, Worker-Absturz, Ausgabeüberlauf und hartem
Abbruch des Elternprozesses. Weitere Prüfungen decken ungültige Abschlussnachrichten,
unbekannte/fremde Sitzungsidentität und nicht bestätigtes Prozessende ab.
Windows-Workspace-Build und Clippy für alle Targets sowie Linux-Clippy für alle
`ssk-winhost`-Targets bestehen. Format-, Diff- und lokale Linkprüfung bestehen;
Linux-Laufzeittests wurden nicht ausgeführt. Keine neuen Abhängigkeiten.

Es wurden ausschließlich private synthetische ETW-Sitzungen verwendet; die
CLI-Regression verwendet außerdem die vorhandene Loopback-Testlast. Keine
Kernel-/Netzwerkprovider oder Firewall-, Routing-, VPN- und Dienständerungen.
Die Ausgabeordner erben weiterhin Rechte und sind nicht gegen einen feindlich
veränderbaren Namensraum gehärtet. Der Job ist keine Sicherheits-Sandbox.

**Nächster Schritt:** geschützte Besitz-/Ausgaberegeln und darauf aufbauende
Wiederherstellung systemweiter Sitzungen. Der Systemstart bleibt bis zu deren
Umsetzung und der isolierten Windows-Abnahme gesperrt. `OPENVPN_NOT_READY` und
die fehlende aktive WFP-Durchsetzung gelten unverändert.

[Prozessüberwachung, Ergebnisvertrag und Grenzen](ETW_CAPTURE_SUPERVISION.md).
Prüfprotokolle: `target/restart-audit/capture-supervision-*`.

## Fortsetzung: eigenständiges UI-Modul (24. September 2026)

Die Oberfläche liegt jetzt außerhalb des Rust-Backends unter `ui/desktop`.
Getrennte Komponenten für Kill-Switch, Audit und Verbindungen erhalten ausschließlich
Anzeigedaten. Ein injizierter Leseadapter verbindet die Präsentationssteuerung mit
einem künftigen Desktop-Host oder der expliziten Entwicklungsvorschau. Komponenten
importieren weder Tauri noch einen Transport. Der Produktions-Importgraph enthält
keine Vorschau; ein ausgefallenes Backend wird nicht durch Beispieldaten ersetzt.

`ssk-ui-contract` enthält die bisherigen Anzeige-DTOs und den versionierten
`PanelSnapshotV1`. Das Modul hat ausschließlich Serde als direkte Laufzeitabhängigkeit.
Die Bridge exportiert Typnamen weiter und übernimmt die Abbildung der Systemtypen.
Ein Metadaten-Test verhindert auch indirekte Abhängigkeiten des Vertrags auf andere
Workspace-Module. Die beiden Daemon-Architekturprüfungen bestehen unverändert.

Sieben geteilte JSON-Szenarien ermöglichen Entwicklung ohne Rust-Build oder Dienst.
Die Vorschau trägt einen permanenten Hinweis auf Beispieldaten. Die reguläre Seite
bleibt ohne Host getrennt. Der UI-Controller behandelt Antwortzeitlimit, veraltete
Beobachtung, konkurrierende Antworten und Schließen der Ansicht; fehlende Daten
ersetzen vorherige Bestätigungen vollständig. Der Vertrag authentifiziert keine
Quelle und erteilt keine Schutzbefugnisse.

**Validierung:** 14 eigenständige Node-Tests sowie 29 Rust-Tests für Vertrag/Bridge
und zwei Daemon-Architekturtests bestanden; ein bestehender Golden-Generator bleibt
ignoriert. Alle sieben Vorschauzustände, Ablauf alter Daten und der reguläre
Einstieg ohne Host wurden im Browser geprüft. Windows-Workspace-Build und Clippy
für alle Targets sowie Linux-Clippy für Vertrag/Bridge bestehen; Linux-Laufzeittests
wurden nicht ausgeführt. Format-/Diff-/lokale Linkprüfungen bestehen. Die gesamte
Workspace-Laufzeitsuite wurde in diesem UI-Schritt nicht erneut ausgeführt.
Ein separater Node-24-CI-Job für Windows und Linux ist ergänzt, noch nicht remote
ausgeführt. Es wurden keine neuen Registry-/npm-Abhängigkeiten hinzugefügt.

**Nächster UI-Schritt:** einen dünnen Desktop-Host und die echte lesende
Dienstanbindung für `get_panel_snapshot_v1` implementieren. Gestaltung und
Komponenten können davon unabhängig weiterentwickelt werden. Systemaufnahme,
OpenVPN-Bereitschaft und aktive WFP-Durchsetzung werden durch diese Vorschau
nicht aktiviert. Die früheren HTML/JS/CSS-Dateien in der Bridge sind ersetzt;
es gibt nur noch ein Frontend als Quelle.

[Modulgrenzen und Datenvertrag](MODULAR_DESKTOP_UI.md),
[lokaler Start und Vorschau](../ui/desktop/README.md).
Prüfprotokolle: `target/restart-audit/modular-ui-*`.

## Fortsetzung: Windows-Desktop und lesender Dienstzugriff (24. September 2026)

`apps/desktop` ist jetzt ein startbarer Tauri-2-Host mit eigenem Cargo-Workspace
und Lockfile. Das gebündelte Frontend bleibt in `ui/desktop`; eine feste Dateiliste
schließt Vorschauseite, Testdaten und Entwicklungsserver aus. Die neue Dienstkarte
zeigt Laufzeitzustand, Version, Profil, Adapteranzahl und optionalen Fehlercode.

`ssk-desktop-client` liest ausschließlich `GetStatus` vom vorhandenen Daemon.
Der Host ermittelt den lokalen benutzerbezogenen Endpunkt, lässt höchstens eine
Abfrage zu und begrenzt Verbindung plus Antwort auf zwei Sekunden. Fehler werden
zu festen Codes. Relative Zustandspfade, unbekannte Antworten und unzulässige
Anzeigedaten werden abgewiesen. Abbruch und Timeout schließen die Verbindung.

Der neue Befehl `get_panel_snapshot_v2` liefert `DesktopSnapshotV2`. Die bisherige
geplante v1-Host-Anbindung wird damit ersetzt: Die real vorhandene Daemon-Antwort
kann keine vollständige Kill-Switch-/Audit-/Verbindungsbeobachtung liefern. V2
enthält daher nur den Dienststatus und lässt keine bestätigte Schutzanzeige zu.
Auch die vorhandenen booleschen Schutzangaben des Daemons werden nicht übernommen.
Der produktive Adapter akzeptiert keine V1-Antworten; die Vorschau kann weiterhin
die bisherigen sieben V1-Zustände und zusätzlich ein V2-Dienstbeispiel darstellen.

App-Manifest und lokale Capability erlauben nur den Lesebefehl im Fenster `main`.
Externe Ursprünge, andere Fenster, Core-Befehle und unbekannte App-Befehle werden
in Tests abgewiesen. Navigation bleibt auf den gebündelten Ursprung beschränkt,
neue Fenster sind gesperrt. Es gibt keine Shell-/Dateisystem-/Prozess-Plugins und
keinen automatischen Daemonstart. Der bestehende Client prüft jedoch noch nicht
die Serveridentität: Diese Anzeige ist Diagnose, keine Herkunftsattestierung.

**Validierung:** 17 Node-Tests, 36 Rust-Tests für Client/Vertrag/Bridge, drei
Daemon-Integration-/Architekturtests und drei Host-Tests bestanden. Der bestehende
Bridge-Golden-Generator bleibt ignoriert. Der sonst ignorierte WebView-Starttest
wurde hier ausdrücklich ausgeführt: Das tatsächlich gebündelte JavaScript rief
über die echte Tauri-Capability den Status einer isolierten Test-Pipe ab. Ein
separater Test verwendete den realen Daemon und prüfte auch dessen Ausfall.
Die Host-Tests benötigten außerhalb der Sandbox Zugriff auf Windows/Tauri-Pfade.
Keine Firewall-, Routing-, VPN-, System-ETW- oder Dienstinstallation erfolgte.

Windows-Host-Build und Host-Clippy sowie Clippy für alle Windows-Workspace-Targets
bestehen. Linux-Clippy für Client und Vertrag besteht; keine Linux-Laufzeittests.
Format- und Diffprüfungen bestehen. Im Browser wurden die neue Dienstkarte,
fehlende Schutzbestätigung, das Entfernen veralteter Daten und die Fehlerkonsole
geprüft. Native Pixel-/Bedienprüfung bleibt offen; der native Starttest belegt den
Aufrufweg. Die gesamte Workspace-Laufzeitsuite wurde nicht erneut ausgeführt.
Ein separater Windows-Host-CI-Job ist ergänzt, noch nicht remote ausgeführt.

**Nächste Schritte:** Serverherkunft und Quellaktualität absichern, dann vollständige
Schutz-/Audit-/Verbindungsbeobachtungen anschließen. Installer, Signierung und
isolierte Windows-Abnahme bleiben offen. Die zweite Maschine ist laut Nutzer
ein Windows-10-Laptop mit 8 GB RAM; zusätzlicher freier Speicher wird gerade
geprüft. Eine Test-VM steht weiterhin nicht bereit. `OPENVPN_NOT_READY`, fehlende
aktive WFP-Durchsetzung und die Sperre systemweiter ETW-Aufnahmen gelten unverändert.

[Startanleitung](../apps/desktop/README.md),
[Daten- und Vertrauensgrenzen](DESKTOP_BACKEND_CONNECTION.md).
Prüfprotokolle: `target/restart-audit/desktop-*`.
