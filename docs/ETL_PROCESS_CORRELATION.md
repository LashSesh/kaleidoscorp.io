# Zeitliche Prozesszuordnung aus ETL-Dateien

Stand: 22. September 2026. Der [ETL-Dateileser](ETL_NETWORK_READER.md) verarbeitet
jetzt zusätzlich klassische Prozessereignisse. Er zählt, wie viele dekodierte
Netzwerkereignisse innerhalb einer beobachteten Prozesshistorie liegen und warum
andere Ereignisse nicht zugeordnet werden können. Die Auswertung bleibt eine
Diagnose unbestätigter Eingabedaten, ohne Identitäts- oder Durchsetzungsbefugnis.
Der zusätzliche Befehl `etl-check` prüft inzwischen einen
[separaten Aufzeichnungsabschluss](ETL_RECORDING_CLOSURE.md), ohne diese
Prozesszuordnung zu einer beglaubigten Identität aufzuwerten.

## Verwendung und Berichtsvertrag

```powershell
cargo run -p ssk-winhost --bin ssk-netobserve -- etl C:\Traces\recording.etl
```

Der ETL-Bericht hat jetzt `schema_version: 2`. Neu sind Prozessereigniszähler,
Abweichungen zwischen Header-/Payload-PID und der Abschnitt `process_correlation`.
Bestehende JSON-Replays (`etw-replay`) behalten ihren eigenen Vertrag und erhalten
dadurch keine Prozesszuordnung. Ein Bericht ist weiterhin keine Eingabe für die
[Verhaltensanalyse](NETWORK_ANALYSIS_BASELINE.md).

`process_correlation.status` ist entweder `evaluated_unverified_input` oder
`unavailable`. Der erste Wert bedeutet, dass der Korrelationsalgorithmus die
vorliegenden Daten auswerten konnte; er bedeutet nicht, dass alle Ereignisse
zugeordnet wurden oder die Aufzeichnung vollständig ist. Bei `unavailable` nennt
`reason` die Ursache und alle bereits dekodierten Netzwerkdatensätze werden als
`invalidated_records` gezählt. Zuordnungszähler bleiben dann null.

| Zähler | Bedeutung |
| --- | --- |
| `start_bounded_records` | Ereignis liegt strikt innerhalb eines mit Start begonnenen, später bestätigten Beobachtungsintervalls |
| `rundown_bounded_records` | Dasselbe mit einem Bestandsereignis als unterer Grenze; tatsächlicher Prozessstart unbekannt |
| `missing_history_records` | Keine verwendbare untere Prozessbeobachtung für die Payload-PID |
| `unclosed_window_records` | Eine spätere Bestätigung derselben Prozessinstanz fehlt |
| `outside_observed_window_records` | Ereignis liegt außerhalb der beobachteten Intervalle, etwa vor Rundown oder zwischen zwei PID-Lebenszeiten |
| `ambiguous_boundary_records` | Zeitstempel fällt genau auf eine Intervallgrenze; Callback-Reihenfolge entscheidet nicht über Zuordnung |
| `no_payload_pid_records` | Netzwerk-Fail-Ereignis ohne Payload-PID; kein Rückfall auf die Header-PID |
| `invalidated_records` | Gesamte bisherige Korrelation wegen Quellenfehler, Widerspruch oder Grenze verworfen |

Diese Kategorien sind disjunkt und ergeben zusammen `network_records`, das mit
`decoded_prefix_records` des ETL-Berichts übereinstimmen muss. Zusätzliche Zähler
beschreiben beobachtete Lebenszeiten, `pid_lifetime_transitions`, End-Ereignisse
ohne passende Vorgeschichte und Idle-Ereignisse. Ein Lebenszeitwechsel zählt eine
beendete und erneut aufgenommene PID-Historie innerhalb dieser Datei; er ist kein
extern beglaubigter Nachweis einer tatsächlichen PID-Wiederverwendung.

Der Bericht enthält nur aggregierte Zahlen. Kernel-Objektadressen, PIDs einzelner
Prozesse, Namen, SIDs und Kommandozeilen werden nicht ausgegeben. Die bisherige
Zählung von TCP/UDP, Retransmit, TCPCopy und nicht zugeordneten Netzwerkfehlern
bleibt separat bestehen.

## Welche Ereignisse verarbeitet werden

Der klassische Process-Provider hat die GUID
`3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c`. Start-/End-Ereignisse beschreiben
Prozesslebenszeiten; DCStart/DCEnd sind Bestandsmeldungen. Die Payload-PID ist
maßgeblich, weil der Ereignisheader beispielsweise den Elternprozess enthalten
kann. [Microsoft: Process](https://learn.microsoft.com/en-us/windows/win32/etw/process).

Der Decoder unterstützt Version 2, 3 und 4 sowie die Opcodes 1, 2, 3 und 4.
Windows TDH liest ausschließlich `ProcessId` und `UniqueProcessKey` über feste
Eigenschaftsnamen und überprüfte Größen. Der Schlüssel ist eine Kernel-
Objektadresse, keine dauerhaft eindeutige Prozesskennung.
[Microsoft: Process-Eigenschaften](https://learn.microsoft.com/en-us/windows/win32/etw/process-v2-typegroup1).
Versionen und relevante Felder wurden zusätzlich gegen die lokal vorhandenen
WMI-Schemas `Process_V2/V3/V4_TypeGroup1` geprüft. Der lokale Nachweis liegt unter
`target/restart-audit/process-correlation-local-schema.json`.

Idle-PID 0 ist bei Rundown zulässig und wird separat gezählt. Netzwerkereignisse
mit PID 0 weist der bestehende Netzwerkdecoder weiterhin ab. Ein fehlender
Schlüssel bei einer anderen PID führt zum Fehler. Es gibt keinen Rückfall auf
Header-PID, Bildname, aktuelle Prozessliste oder eine nachträgliche
`OpenProcess`-Abfrage. Variable Prozessdaten wie SID und Kommandozeile werden
nicht dekodiert; der Decoder bestätigt nicht die Gültigkeit sämtlicher ungenutzter
Payload-Felder.

Terminate-Anforderungen, Prozess-Leistungszähler und das nachgelagerte
Defunct-Ereignis werden als Hilfsereignisse gezählt. Daraus entstehen keine Start-
oder Endbelege. Unbekannte Versionen/Opcodes, unerwartete Zusatzdaten oder
unauflösbare TDH-Eigenschaften beenden die Verarbeitung ausdrücklich.

Bei allen klassischen Netzwerk- und Prozessabfragen wird die bereits geprüfte
32-/64-Bit-Breite aus dem Ereignisheader mit `TDH_CONTEXT_POINTERSIZE` ausdrücklich
an TDH übergeben. Die Breite wird nicht aus der ausführenden Maschine abgeleitet.
[Microsoft: TDH-Kontext](https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-tdh_context_type).
Eine parallele lokale Prüfung zeigte trotz dieses Kontexts widersprüchliche
Größen von Pointer-Eigenschaften. Deshalb teilen sich alle nativen Netzwerk- und
Prozessdecoder eine prozessweite Sperre für die vollständige Datensatzdekodierung.
Die parallelen Aufrufer bleiben Bestandteil der Regressionsprüfung. Eine vergiftete
Sperre liefert einen Fehler; die Größenprüfung wird nicht aufgeweicht.

## Regeln der zeitlichen Zuordnung

Die Historie gehört ausschließlich zu einem Dateidurchlauf. Sie wird weder über
Dateien zusammengeführt noch als fortlaufende Live-Identität gespeichert.

1. Ein Start öffnet für `(PID, beobachteter Schlüssel)` eine neue Lebenszeit.
   Ein weiteres Start-Ereignis ohne beobachtetes Ende ist ein Widerspruch, auch
   bei identischem Schlüssel. Ein späterer Start nach Ende erzeugt eine neue
   Lebenszeit, selbst wenn Windows dieselbe PID und Objektadresse wiederverwendet.
2. Ein erstes Bestandsereignis bildet ausschließlich eine untere Beobachtungsgrenze
   zu seinem eigenen Zeitstempel. Davor liegende Netzwerkereignisse werden nicht
   rückwirkend zugeordnet. Der tatsächliche Erstellungszeitpunkt bleibt unbekannt.
3. Ein passendes weiteres Bestandsereignis bestätigt dieselbe beobachtete
   Lebenszeit bis zu seinem Zeitstempel. DCEnd bedeutet dabei nicht, dass der
   Prozess beendet wurde. Ein passendes End-Ereignis schließt die Lebenszeit.
4. Für eine Zuordnung muss der Netzwerkzeitpunkt strikt zwischen der unteren
   und einer späteren Bestätigung liegen. Ein Dateiende allein ist keine solche
   Bestätigung. Gleichzeitige Start-/End-/Netzwerkereignisse werden an Grenzen
   als mehrdeutig behandelt, unabhängig von ihrer Callback-Reihenfolge.
5. Ein Ende ohne aktive Vorgeschichte liefert keinen rückwirkenden Start.
   Widersprüchliche Schlüssel bei einer aktiven PID, rückläufige Zeiten relevanter
   Ereignisse und Ressourcenüberschreitungen machen die Korrelation unbrauchbar.
   Ereignisse werden nicht sortiert und alte Belege nicht zur Platzgewinnung entfernt.

Die Zähler entstehen erst nach dem Dateidurchlauf und `CloseTrace`. Ein später
LostEvent-Marker, ein Decoderfehler oder ein fehlgeschlagener Abschluss verwirft
sämtliche Zuordnungen dieses Durchlaufs. Dadurch kann ein früher plausibler
Präfix nicht als weiterhin gültige Prozesszuordnung ausgegeben werden.

## Grenzen und noch fehlende Nachweise

Zusätzlich zu den bisherigen ETL-Grenzen gelten höchstens 10.000 Prozessprovider-
Ereignisse, 4.096 beobachtete Lebenszeiten und 8 KiB Payload je Prozessereignis.
Die Historie hält nur die benötigten Identitätshinweise und Zeitpunkte im Worker.
Netzwerkbeobachtungen bleiben auf 10.000 begrenzt. Der Bericht bleibt unter der
bestehenden 16-KiB-Grenze; Prozess-, Speicher- und Zeitbegrenzung gelten unverändert.

Auch eine vollständig ausgewertete Historie beweist nicht, dass Start-/End-
Provider vollständig aktiviert waren, kein Ereignis vor dem Import entfernt wurde
oder die Datei echt ist. Die acht bisherigen Vertrauens-/Berechtigungsfelder,
einschließlich `process_identity_verified`, `coverage_verified`,
`baseline_compatible` und `enforcement_active`, bleiben ausnahmslos `false`.
Die Zuordnung ist kein Nachweis von ausführbarer Datei, Signatur oder Benutzer.

Prüfungen decken PID-/Schlüssel-Wiederverwendung, verschachtelt eintreffende PIDs,
fehlende Starts/Enden, Rundown ohne Rückdatierung, gleiche Zeitstempel,
Widersprüche, späte Verluste, Zeitregression, Idle-PID und Ressourcenlimits ab.
Echte Windows-TDH-Aufrufe prüfen synthetische Prozessereignisse in allen
24 Kombinationen aus Version, Opcode und Pointerbreite. Gemischte native
Prozess-/Netzwerk-Callbacks prüfen die Einbindung; eine parallele Prüfung mischt
32- und 64-Bit-Ereignisse. Die bestehenden CLI-Prüfungen verwenden weiterhin nur
eine private ETL-Testdatei ohne Kernel-/Netzwerkprovider.

**Weiter offen:** die gemeinsame Abnahme mit echten Kernel-Netzwerk- und
Prozessaufzeichnungen, absichtlich erzeugten Verlusten und tatsächlich
wiederverwendeten PIDs in einer isolierten Windows-Umgebung. Diese Umgebung fehlt
weiterhin. Als nächster Schritt braucht die Beobachtungsquelle einen überprüfbaren
Aufzeichnungsabschluss mit Provider-/Verlustnachweisen und ein reproduzierbares
Abnahmeszenario. Erst danach ist eine begründete Verbindung zur Verhaltensanalyse
möglich. WFP-Durchsetzung und `OPENVPN_NOT_READY` bleiben unverändert.

Lokale Prüfprotokolle: `target/restart-audit/process-correlation-*`.

**Validierter Stand:** 1.524 Windows-Workspace-Tests bestanden, 0 fehlgeschlagen,
1 bereits zuvor ignorierter Generator; 146 Testsuiten. Neu sind 26 Modulprüfungen:
14 zur Historie, fünf zum Prozessschema, sechs zur nativen Einbindung einschließlich
parallelem TDH-Zugriff und eine zur erweiterten Berichtsschnittstelle. Die bisherigen
ETL-CLI-Prüfungen prüfen außerdem Schema-Version 2 und den neuen Korrelationsstatus.
Windows-Workspace-Build und Clippy für alle Targets mit `-D warnings`, Linux-Clippy
für alle `ssk-winhost`-Targets, Format-/Diff- und lokale Dokumentationslinkprüfung
bestehen. Linux-Tests wurden nicht ausgeführt. Es kamen keine Abhängigkeiten hinzu;
der Daemon behält seine 17 Workspace-Abhängigkeiten.
