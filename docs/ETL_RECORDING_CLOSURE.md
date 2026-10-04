# Abschlussprüfung für importierte ETL-Aufzeichnungen

Stand: 22. September 2026. `ssk-netobserve etl-check` prüft eine vorhandene ETL-Datei
gegen einen separaten JSON-Abschlussbericht des Aufzeichners. Unvollständige und
widersprüchliche Angaben werden sichtbar. Der Befehl startet keine Aufzeichnung.

```powershell
cargo run -p ssk-winhost --bin ssk-netobserve -- etl-check C:\Traces\recording.etl C:\Traces\closure.json
```

Die Ausgabe verwendet ein eigenes Schema, Version 1, mit zwei Teilen:

- `etl`: unveränderter [ETL-Berichtsvertrag, Version 2](ETL_NETWORK_READER.md),
  einschließlich [zeitlicher Prozesszuordnung](ETL_PROCESS_CORRELATION.md).
- `closure`: Abschlussprüfung, Version 1. `consistent_unverified` bedeutet,
  dass Datei und Abschlussangaben den Konsistenzregeln entsprechen.
  `unavailable` nennt die gefundenen Probleme in `issues`.

Exitcode 0 bedeutet lediglich, dass ein Bericht erstellt wurde; **beide
Statuswerte müssen ausgewertet werden**. Exitcode 2 bezeichnet ungültige Eingaben,
Datei-/Workerfehler oder eine verletzte Ressourcengrenze. Die Abschlussprüfung
verändert die ETL-Diagnose nicht und aktiviert keine Schutzfunktion.

## Eingabevertrag

Das [synthetische JSON-Beispiel](examples/etl-closure.json) wird von den Modultests
eingelesen. Sein Hash gehört zu den drei Bytes `abc`, **nicht zu einer ETL-Datei**.
Es ist ein Schema-Beispiel, keine bestandene Windows-Aufzeichnung. Ein echter
Aufzeichner muss die Werte aus seinen eigenen Aufrufen und der abgeschlossenen
Datei ermitteln; Nullen und Erfolgsangaben dürfen nicht aus dem Beispiel übernommen
werden. Ein produktiver Aufzeichner ist noch nicht implementiert.
Eine [ausführbare private Abnahme und Loopback-Testlast](ETW_CAPTURE_PREPARATION.md)
stehen inzwischen über `ssk-netcapture` bereit; sie starten keine Systemaufnahme.

| Feld | Bedeutung |
| --- | --- |
| `schema_version` | exakt 1 |
| `source` | `synthetic_fixture` oder `unverified_controller_export`; beide unbestätigt |
| `profile` | exakt `process_network_v1` |
| `file.bytes`, `file.sha256` | Länge und SHA-256 der geschlossenen Datei; 64 kleine Hex-Zeichen |
| `intent` | angeforderte Sitzungs-GUID, Clock-Typ, `LogFileMode` und `EnableFlags` |
| `owns_session_from_start` | Erklärung, dass der Aufzeichner die Sitzung selbst erfolgreich gestartet hat |
| `configuration_unchanged` | Erklärung, dass die Konfiguration bis zum Stopp unverändert blieb |
| `start_status` | unveränderter Rückgabecode von `StartTraceW` |
| `query_after_start` | `ControlTraceW(QUERY)` nach dem Start, vor der Testlast |
| `stop` | abschließender `ControlTraceW(STOP)`-Aufruf |

Beide Momentaufnahmen enthalten `api_status` und `properties`. Letzteres enthält
`session_guid`, `log_file_mode`, `enable_flags`, `events_lost`, `log_buffers_lost`,
`realtime_buffers_lost` und `buffers_written` aus `EVENT_TRACE_PROPERTIES`.
Die Zähler sind kumulative native `u32`-Werte. `QUERY` liefert Eigenschaften und
Statistik; `STOP` beendet die Sitzung. Auch `ERROR_MORE_DATA` beim Stopp kann die
Sitzung bereits beendet haben, liefert für diesen Vertrag aber keinen
erfolgreichen, vollständigen Abschluss.
[Microsoft: ControlTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew).

Fehlende optionale Abschlussangaben bleiben unbekannt und führen zu `unavailable`.
Fehlende einzelne Statistikfelder, zusätzliche Felder, doppelte JSON-Schlüssel,
unbekannte Schema-/Profilwerte und Werte außerhalb ihrer Grenzen werden als
ungültige Eingabe abgewiesen. Sitzungs-GUIDs sind nicht null und haben das
kanonische Format mit kleinen Hex-Zeichen und Bindestrichen.

## Profil und Konsistenzregeln

Profil v1 verlangt einen eigenen System-Logger mit QPC-Zeitbasis (`clock_type=1`)
und sequenzieller Datei. Der Modus ist `0x02000001`; die dokumentierte sequenzielle
Variante `0x02000000` gilt als gleichwertig. Andere Modusbits sind unzulässig.
Die vordefinierten Kernel-/Global-Logger-GUIDs werden abgewiesen. Microsoft
beschreibt eigene SystemTraceProvider-Sitzungen mit
`EVENT_TRACE_SYSTEM_LOGGER_MODE` und einer eigenen GUID.
[SystemTraceProvider](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session),
[Logging modes](https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants).

`EnableFlags` muss exakt `0x10010001` sein: `PROCESS | NETWORK_TCPIP | NO_SYSCONFIG`.
`NETWORK_TCPIP` umfasst TCP und UDP; `NO_SYSCONFIG` unterdrückt die zusätzliche
Systemkonfigurationsaufzeichnung. Weitere Ereignisgruppen akzeptiert dieses
Profil nicht. Die Flags haben diese Bedeutung bei System-Loggern, nicht bei
beliebigen Benutzerprovidern. Die Verlustzähler unterscheiden verlorene Ereignisse,
nicht geschriebene Logpuffer und nicht gelieferte Echtzeitpuffer.
[EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties).

Die Prüfung verlangt:

1. Passende Dateilänge und Prüfsumme, beide Eigentums-/Kontinuitätserklärungen auf
   `true` sowie erfolgreiche Start-, Abfrage- und Stoppangaben.
2. Gleiche Sitzungs-GUID und passende Konfiguration in beiden Statistikständen.
3. Alle drei Verlustzähler an beiden Grenzen gleich null. Anfängliche Verluste
   werden nicht abgezogen. Rückläufige Zähler einschließlich `buffers_written`
   werden als Widerspruch erkannt, nicht als Überlauf repariert.
4. Mindestens einen geschriebenen Puffer im Stopp-Ergebnis sowie passende
   Clock-/Modusangaben im ETL-Header.
5. `etl.status=decoded_file`. Fehler, Verlustmarker, unvollständige Header oder
   fehlende unterstützte Netzwerkereignisse bleiben Ausschlussgründe.

Die Headerzähler `TRACE_LOGFILE_HEADER.EventsLost/BuffersLost` bleiben getrennt von
den Controllerzählern. Zwischen unterschiedlich benannten Zählern dieser APIs
wird keine unbewiesene Gleichheit verlangt.

## Grenzen

Beide Eingaben müssen vorhandene reguläre lokale Dateien sein. JSON ist auf
16 KiB, ETL auf 64 MiB begrenzt. Geräte-/UNC-/Stream-Pfade werden abgewiesen.
Beide Dateien werden ohne Schreib-/Löschfreigabe geöffnet. Die Prüfsumme wird
vom gehaltenen ETL-Handle mit einem 32-KiB-Puffer berechnet; dieser Handle bleibt
während der nativen Auswertung offen. Der Leser läuft in seinem überwachten Job.
Hashen und synchrone Dateioperationen liegen außerhalb der zehnsekündigen
Worker-Deadline.

`file_binding_matches=true` bestätigt die Übereinstimmung der gelesenen Dateibytes
mit der angegebenen Prüfsumme und Länge. Wer Datei und JSON ändern kann, kann eine
passende Prüfsumme erstellen. Sitzungszugehörigkeit, Herkunft und unveränderte
Provider zwischen zwei Momentaufnahmen sind damit nicht beglaubigt. Die Prüfung
schützt nicht gegen einen angreifergesteuerten Dateisystem-Namensraum oder einen
kompromittierten nativen Parser.

Deshalb bleiben `controller_authenticity_verified`, `provider_continuity_verified`,
`loss_completeness_verified`, `coverage_verified`, `baseline_compatible` und
`enforcement_active` immer `false`. Diese Ausgabefelder gehören nicht zum
deserialisierbaren Eingabevertrag. Die Vertrauensfelder des ETL-Berichts bleiben
ebenfalls falsch. Es gibt keine Umwandlung in den
[Verhaltensanalyse-Vertrag](NETWORK_ANALYSIS_BASELINE.md).

## Reproduzierbare Abnahme

Die lokale Abnahme verwendet nur einen privaten Logger im eigenen Testprozess.
Er aktiviert einen eigenen synthetischen Benutzerprovider, fragt die Sitzung ab,
schreibt ein Testereignis, stoppt die Sitzung und bildet den Hash der Windows-Datei.
Eine Drop-Sicherung beendet die eigene Sitzung auch bei vorzeitigem Testabbruch.
Kernel-/Netzwerkprovider werden nicht gestartet.

```powershell
cargo test -p ssk-winhost --lib network_etw::etl::closure --offline --locked
cargo test -p ssk-winhost --test network_etl --offline --locked
```

| Fall | Erwartetes Ergebnis |
| --- | --- |
| Konsistentes synthetisches Modell im Modultest | `consistent_unverified`; alle Vertrauensfelder falsch |
| Echte private Windows-Datei mit Abfrage-/Stoppzählern | Dateibindung stimmt; `unsupported_profile_configuration`, `etl_unavailable` |
| Geänderte Prüfsumme oder Länge | `file_binding_mismatch` |
| Fehlender oder gescheiterter Stopp, auch Status 234 | `stop_unsuccessful_or_missing` |
| Positive Verluste in Anfangs- oder Endstand | `loss_reported` |
| Rückläufige Zähler | `counter_regression` |
| Andere Sitzung oder Providerflags | `session_configuration_mismatch` |
| Unpassender Header / gescheiterte ETL-Auswertung | `etl_header_mismatch` / `etl_unavailable` |
| Fremde Vertrauensfelder, fehlende Zähler, zu große oder zum Schreiben offene Datei | Exitcode 2 |

Für die **noch ausstehende isolierte Windows-Abnahme** gilt folgender Ablauf.
Der System-Trace-Controller samt Absturzüberwachung ist noch zu implementieren;
die feste Loopback-Testlast steht bereits bereit. Dies ist kein bereits
ausführbarer System-Capture-Befehl:

1. Frischen VM-Snapshot verwenden, Windows-Build und Programmversion festhalten.
   Ein nur dem Test zugängliches Ausgabeverzeichnis anlegen. Eine benannte eigene
   System-Logger-Sitzung mit eigener GUID, obigen Flags und festem Größen-/Zeitbudget
   starten. Bei Namenskonflikt abbrechen; keine fremde Sitzung übernehmen/stoppen.
2. Direkt danach `QUERY` erfassen. Feste lokale TCP-/UDP-Testlast mit IPv4/IPv6 aus
   separaten Prozessen ausführen. Einen Prozess innerhalb der Aufnahme starten
   und beenden; einen weiteren vorher starten, um Bestandsereignisse zu prüfen.
   Sollmengen getrennt nach Anwendungsvorgängen dokumentieren; ETW-Größen sind
   keine Anwendungsbytes.
3. Eigene Sitzung stoppen, native Statistik und Rückgabecode sichern. Nach dem
   Dateischluss Hash und Abschlussbericht erstellen. `etl-check` ausführen und
   Dekodierung, Prozesszuordnung und Status prüfen. Exitcode/Hash allein genügen
   nicht für eine positive Abnahme.
4. In Kopien fehlende Abschlussdaten, fremde GUID, geänderte Flags, Hashfehler,
   Zählerregression und Verluste injizieren; obige Fehler erwarten. Das testet
   den Prüfer, keine echten Windows-Verluste.
5. Separat reale Verluste, abgebrochene Erfassung, Provideränderungen und
   tatsächlich beobachtetes PID-Recycling unter kontrollierter Last erzeugen.
   Rohdaten und Sollbeobachtungen sichern; nicht erzeugte Fälle bleiben offen.
   Andere Windows-Builds und Architekturen gesondert abnehmen.

Eigene Erfassung, kontrollierte Herkunft und VM-Ergebnisse fehlen noch.
Netzwerkabdeckung, OpenVPN-Bereitschaft und aktive Membran-/Firewallwirkung bleiben
eigenständige offene Produktaufgaben.
