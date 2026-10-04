# ETW-Netzwerkereignisse: Decoder und Eingangsprüfung

Stand: 22. September 2026. Der nächste Baustein nach der
[Windows-Momentaufnahme](WINDOWS_NETWORK_OBSERVATION.md) ist implementiert:
`ssk-winhost::network_etw` und `ssk-netobserve etw-replay`.

Er verarbeitet **synthetische oder unbestätigt exportierte Ereignisdaten** mit
Windows Trace Data Helper (TDH). Der JSON-Replay-Befehl startet keine ETW-Sitzung
und empfängt keine Live-Ereignisse. Ein separater
[überwachter ETL-Dateileser](ETL_NETWORK_READER.md) ist inzwischen implementiert.
Es gibt keine Kopplung an Daemon, Broker,
Policy oder die [Verhaltensanalyse](NETWORK_ANALYSIS_BASELINE.md).

## Ergebnis der Quellenprüfung

Die klassischen Kernel-Provider sind geeignete Kandidaten für zusätzliche
Netzwerkdiagnose. Untersucht und im Decoder zugelassen sind ausschließlich:

| Provider | GUID | Version | Ereignisse |
|---|---|---|---|
| TcpIp | `9a280ac0-c8e0-11d1-84e2-00c04fb998a2` | 2 | Send, Receive, Connect, Accept, Disconnect, Retransmit, Reconnect, TCPCopy über IPv4/IPv6 sowie Fail |
| UdpIp | `bf3a50c5-a9c9-4988-a005-2df0b7c80f80` | 2 | Send/Receive über IPv4/IPv6 sowie Fail |

Die Dokumentation beschreibt die Aktivierung über `EVENT_TRACE_FLAG_NETWORK_TCPIP`.
Dies wird hier nicht ausgeführt. Die Zuordnung der Ereignistypen ist unter
[TcpIp](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip) und
[UdpIp](https://learn.microsoft.com/en-us/windows/win32/etw/udpip) festgehalten.
Andere Provider, insbesondere ähnlich benannte Manifest-Provider, werden nicht
anhand ihres Namens gleichgesetzt. Unbekannte Versionen und Opcodes sind Fehler.

Drei Befunde verhindern eine unmittelbare Verwendung als Sicherheitsentscheidung:

1. **Header-PID ist keine sichere Netzwerkzuordnung.** Microsoft weist darauf hin,
   dass Netzwerkereignisse von anderen Threads protokolliert werden können.
   Der Decoder liest deshalb ausschließlich die Eigenschaft `PID` aus den
   Ereignisdaten. Eine Abweichung zum Header wird gezählt; fehlende Payload-PID,
   PID 0 oder `u32::MAX` werden nicht durch den Header ersetzt.
2. **Fail ist kein vollständiges Verbindungsversuchsergebnis.** Das dokumentierte
   [TcpIp_Fail](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-fail)
   enthält nur Adressfamilie und Fehlercode. Es fehlen PID und Endpunkte.
   [UdpIp_Fail](https://learn.microsoft.com/en-us/windows/win32/etw/udpip-fail)
   hat dieselbe Einschränkung. Solche Ereignisse bleiben unzugeordnete Diagnosen;
   sie erhöhen keine anwendungsbezogene Fehlerquote.
3. **Verlustzähler müssen aus der richtigen Schnittstelle kommen.**
   `EVENT_TRACE_LOGFILEW.EventsLost` wird laut
   [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew)
   nicht verwendet. Ein Nullwert dort beweist keinen verlustfreien Trace.
   Die relevanten Sitzungszähler stehen in
   [EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties):
   `EventsLost`, `LogBuffersLost` und `RealTimeBuffersLost`. Ein künftiger Controller
   muss sie für seine eigene Sitzung abfragen; eigene Queue-Verluste kommen hinzu.

## Metadatengestützte Auflösung

Der Decoder akzeptiert klassische Header mit genau einer 32-/64-Bit-Angabe und
einer begrenzten Menge zusätzlicher Metadatenflags. WPP-, String-only-, private
und umgedeutete GUID-Header sowie nicht mitgelieferte Extended-Data werden abgewiesen.
Er konstruiert für das Offline-Replay einen eigenen `EVENT_RECORD` mit ausschließlich
eigenem, begrenztem Speicher. Fremde Pointer werden nicht importiert.

[TdhGetPropertySize](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetpropertysize)
und [TdhGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetproperty)
lösen feste Eigenschaftsnamen auf. Die erwartete Größe muss vor dem Lesen genau
passen: beispielsweise vier Bytes für PID, zwei für einen Port und vier/acht für
den Korrelationswert. Die maximale einzelne Ausgabe umfasst 16 Bytes. Fehlende
Metadaten, falsche Größen oder ein TDH-Fehler führen zum Abbruch des Decodierens.
Es gibt keinen automatischen Rückfall auf geratene Bytepositionen.

Diese Entscheidung hat einen konkreten Grund: Die vereinfachten MOF-Darstellungen
und Microsofts [PerfView-Decoder](https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs)
zeigen nicht überall dieselbe Reihenfolge der hinteren Korrelationsfelder, etwa
bei `TcpIpV6TraceData`. TDH verwendet die lokal auflösbaren Metadaten. Ob diese mit
realen Ereignissen jedes unterstützten Windows-Builds übereinstimmen, muss zusätzlich
an echten Aufzeichnungen und im Vergleich mit einem unabhängigen Decoder geprüft
werden. Die hier erzeugten Testdaten ersetzen diesen Nachweis nicht.

IP-Adressen und Netzwerkports werden getrennt gelesen. IPv6-Scope-IDs fehlen in
diesen Ereignissen und werden nicht erfunden. Die Felder bleiben Quelle/Ziel laut
Provider; sie werden nicht ungeprüft als lokale/entfernte Socketseite umbenannt.
`connid` ist nur ein opaker Korrelationshinweis. `seqnum` ist kein Nachweis einer
lückenlosen ETW-Ereignisfolge. Eine PID allein beweist weiterhin keine Prozessinkarnation.

## Replay ausführen

```powershell
cargo run -p ssk-winhost --bin ssk-netobserve --offline --locked -- etw-replay docs/examples/etw-network-replay.json
```

Das [Beispiel](examples/etw-network-replay.json) ist vollständig synthetisch. Es
enthält vier Ereignisse: TCP-Senden mit gemeldeter Größe 1.500, TCP-Retransmit mit
1.000, UDP/IPv6-Empfang mit 128 und ein nicht zuordenbares TCP-Fehlerereignis.
Der Bericht hält diese Größen getrennt. Die Summe von Senden und Retransmit wird
nicht als zusätzlich gesendete Anwendungsdaten ausgegeben.

`decoded_input` bedeutet ausschließlich: Die deklarierte Eingabe erfüllte diese
Prüfungen und die abgefragten Felder ließen sich auflösen. Es bedeutet weder
vollständige Erfassung noch unauffälligen oder erlaubten Verkehr. Der Bericht hat
kein Malware-Urteil; folgende Angaben bleiben immer falsch:

```json
{
  "trace_authenticity_verified": false,
  "process_identity_verified": false,
  "coverage_verified": false,
  "application_byte_counts_verified": false,
  "attempt_outcomes_available": false,
  "baseline_compatible": false,
  "enforcement_active": false
}
```

Die Ausgabe enthält nur aggregierte Diagnosezähler, keine Payloads, IP-Adressen,
Prozesslisten oder Korrelationspointer. Der interne Decoder liefert einzelne
dekodierte Werte für spätere Tests, ohne sie zu authentifizieren. Größen aus dem
Providerfeld `size` werden ausdrücklich als gemeldete Größen bezeichnet: Nutzdaten,
Retransmission, Offloading und Aggregation brauchen noch einen validierten Zählvertrag.
Die Zähler gelten für den erklärten Export insgesamt, nicht für eine belegte
Anwendung oder einen bestimmten Flow. Mehrere Prozessinkarnationen mit derselben
PID werden hier noch nicht auseinandergehalten.

Exitcode 0 heißt **Bericht erzeugt**, auch bei `unavailable`. Exitcode 2 bezeichnet
ungültige JSON-/Envelope-Eingaben oder Datei-/Ausgabefehler. Auf Nicht-Windows kann
kein TDH-Decodieren stattfinden; ein ansonsten gültiger Batch meldet dafür
`unsupported_platform`. Hilfe und Prüfungen ohne TDH bleiben verfügbar.

TDH benötigt Zugriff auf die lokale Metadatenquelle. In der eingeschränkten
Entwicklungssandbox lieferte die erste Abfrage `ERROR_NOT_FOUND` (1168); außerhalb
der Sandbox gelang dieselbe lesende Prüfung. Ein solches Ergebnis bleibt sichtbar
`unavailable`; das Werkzeug verändert keine Berechtigungen oder WMI-Einstellungen.

## Eingangs- und Verlustvertrag

Die Eingabe ist ein eigenes JSON-Exportformat, **kein nativer ETL-Reader**. Sie erklärt
Quell-Epoche, QPC-Frequenz, einen halboffenen Bereich `[start_ticks, end_ticks)`,
erwartete Anzahl, Abschluss und Verlustzähler zu Beginn/Ende. Diese Angaben sind
Behauptungen des Exporteurs, kein Herkunftsnachweis. Zulässige Herkunftswerte sind
`synthetic_fixture` und `unverified_export`; eine Eingabe kann sich nicht als
verifizierte OS-Erfassung ausgeben.

- Fehlende Verlustzähler bleiben unbekannt. Jeder von null verschiedene Ereignis-,
  Datei-/Echtzeitpuffer- oder Verbraucherverlust verwirft den Batch für diese
  Auswertung. Sinkende Zähler zeigen eine unzulässige Rücksetzung derselben Epoche.
- Fehlender Abschluss, abweichende Anzahl und eine leere Aufzeichnung ergeben
  `unavailable`, bevor TDH aufgerufen wird.
- Die Export-Ordinals beginnen bei null und wachsen lückenlos. Sie erkennen keine
  Verluste, die bereits vor der Nummerierung entstanden sind.
- Zeiten dürfen sich wiederholen, aber nicht zurücklaufen oder außerhalb des
  erklärten Bereichs liegen. Es wird nicht nachträglich sortiert, um Lücken oder
  Umordnung zu verbergen. Die QPC-Frequenz muss ausdrücklich angegeben sein.
- Beim ersten Ereignisfehler endet die Verarbeitung. Bereits dekodierte Zähler
  bleiben als `decoded_prefix_records` sichtbar, zusammen mit `unavailable`.
  Spätere gültige Ereignisse können den Fehler nicht zurücksetzen.
- 1 MiB Dateigrenze, höchstens 512 Ereignisse, 256 Payload-Bytes je Ereignis,
  höchstens 60 Sekunden deklarierter Bereich. Der Datei-Leser liest maximal
  1 MiB plus ein Prüfbyte. Unbekannte und doppelte JSON-Felder werden abgewiesen.
- Fünf Sekunden Decodierbudget, vor und nach jedem Datensatz geprüft. Ein einzelner
  synchroner TDH-Aufruf kann damit nicht präemptiv unterbrochen werden. Für einen
  späteren Dienst ist ein beaufsichtigter Worker mit Abbruch-/Neustartpfad erforderlich.

## Nächster Schritt

Die rein lesende ETL-Quelle mit kontrollierter Worker-Lebensdauer ist im
[ETL-Dateileser](ETL_NETWORK_READER.md) umgesetzt; TDH erhält dort die ursprünglichen
Callback-Metadaten. Die [zeitliche Korrelation von Prozessstart/-ende und Rundown](ETL_PROCESS_CORRELATION.md)
ist inzwischen als begrenzte Diagnose implementiert; eine nachträgliche
`OpenProcess`-Abfrage darf historische PID-Wiederverwendung nicht verdecken.
[Microsoft: Process-Ereignisse](https://learn.microsoft.com/en-us/windows/win32/etw/process).

Erst echte Aufzeichnungen mit bekannten Verbindungen können Byte-Zählung, IPv6,
Offloading und Fensterabschluss belegen. Vorher bleibt die bestehende Baseline
abgekoppelt. Die WFP-Durchsetzung und isolierte Windows-Abnahme bleiben gesondert offen.

## Geprüfter Stand

28 neue Prüfungen bestehen: 24 Modulprüfungen und vier CLI-Integrationsprüfungen.
Die Windows-TDH-Prüfungen decken sämtliche zugelassenen Opcodes, beide IP-Versionen
und 32-/64-Bit-Pointerbreiten mit **synthetischen** Ereignissen ab. Hinzu kommen
unterschiedliche Header-/Payload-PIDs, nicht zugeordnete Fehlerereignisse,
abgeschnittene Daten, falsche Eigenschaftsgrößen, unbekannte Formate, Verlust,
Zeit-/Ordinalfehler, Eingabegrenzen und die getrennte Zählung von Retransmit/TCPCopy.
Für Zeitüberschreitungen und Verlust werden private Testzugänge verwendet;
real erzeugte ETW-Verluste sind damit noch nicht nachgewiesen.

Die vollständige Windows-Workspace-Suite besteht mit **1.478 bestandenen Tests,
0 Fehlern und 1 bereits zuvor ignorierten Generator**. Windows-Build und
Workspace-Clippy für alle Targets mit `-D warnings`, Linux-Clippy für alle Targets
von `ssk-winhost`, Format-/Diff-Prüfung und lokale Dokumentationslinks bestehen.
Linux-Tests wurden hier nicht ausgeführt. Es wurde nur ein Feature der bereits
verwendeten `windows-sys`-Version aktiviert; keine Registry-Version wurde angehoben.
Die 17 Workspace-Abhängigkeiten des Daemons bleiben unverändert.

Das gebaute CLI liefert für das Beispiel `decoded_input`, vier dekodierte Datensätze
und drei Header-/Payload-PID-Abweichungen. Der Bericht wurde vom vorhandenen
Analyse-Replay mit Exitcode 2 abgewiesen. Lokale Protokolle liegen unter
`target/restart-audit/etw-decoder-*`, der Beispielbericht unter
`target/restart-audit/etw-decoder-example-report.json`.
