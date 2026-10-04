# ETL-Dateileser mit überwachtem Worker

Stand: 22. September 2026. `ssk-netobserve etl <recording.etl>` liest eine vorhandene
Windows-Aufzeichnung über `OpenTraceW` und `ProcessTrace`. Unterstützte klassische
TCP-/UDP-Ereignisse werden mit dem [TDH-Decoder](ETW_NETWORK_DECODER.md) ausgewertet.
Der Befehl startet keine Aufzeichnung und ist nicht an Daemon, Broker oder
[Verhaltensanalyse](NETWORK_ANALYSIS_BASELINE.md) angeschlossen.
Eine [zeitliche Prozesszuordnung](ETL_PROCESS_CORRELATION.md) ergänzt inzwischen
die Diagnose. Der ETL-Bericht verwendet dafür jetzt Schema-Version 2.
`etl-check <recording.etl> <closure.json>` ergänzt eine separate
[Abschlussprüfung mit Dateibindung und Controllerangaben](ETL_RECORDING_CLOSURE.md).
Dieser zusätzliche Bericht bestätigt nur Konsistenz, keine Herkunft oder Abdeckung.

## Bedienung und Ergebnis

```powershell
cargo run -p ssk-winhost --bin ssk-netobserve -- etl C:\Traces\recording.etl
```

Die Eingabe muss eine vorhandene, geschlossene Datei auf einem lokalen Laufwerk
sein. Der Leser akzeptiert 1 Byte bis 64 MiB. Explizite UNC-/Gerätepfade und
alternative Datenströme werden abgewiesen. Er öffnet die Datei ohne Schreib- und
Löschfreigabe und ermittelt den endgültigen Pfad vom geöffneten Handle. Diese
Dateisperre bleibt während der Auswertung bestehen; laufende Aufzeichnungen mit
einem offenen Schreibhandle werden nicht eingelesen.

Exitcode 0 bedeutet, dass ein JSON-Bericht erstellt wurde. Entscheidend ist dessen
`status`: `decoded_file` bedeutet ausschließlich, dass Windows die Datei vollständig
durchlaufen hat und der Decoder die ausgewählten Ereignisse innerhalb der Grenzen
verarbeiten konnte. `unavailable` enthält den ersten Fehler und gegebenenfalls
Zähler eines bereits dekodierten Präfixes. Eine Datei ohne unterstützte
Netzwerkereignisse ist ebenfalls `unavailable`.

Exitcode 2 bezeichnet eine unzulässige/unerreichbare Eingabe, einen Startfehler,
Worker-Absturz, Zeit-/Ausgabeüberschreitung oder einen ungültigen Worker-Bericht.
In diesen Fällen wird kein Teilbericht als erfolgreicher Bericht ausgegeben.
Der Bericht enthält aggregierte Zähler, keine Payloads, Endpunkte oder Dateipfade.

## Grenzen und Prozesslebensdauer

| Grenze | Wert / Verhalten |
| --- | --- |
| Dateigröße | 64 MiB |
| Verarbeitete Ereignis-Callbacks | höchstens 100.000 einschließlich anderer Provider |
| Ausgewählte TCP-/UDP-Datensätze | höchstens 10.000 |
| Payload je ausgewähltem Ereignis | höchstens 256 Bytes |
| Worker-Deadline | 10 Sekunden, durch den Elternprozess überwacht |
| Beobachtung nach Abbruch | zusätzlich höchstens 1 Sekunde auf Prozessende warten |
| Privater zugesicherter Speicher des Workers | Windows-Job-Limit von 256 MiB |
| Worker-Ausgabe | höchstens 16 KiB über eine anonyme Pipe |
| Nachfolgeprozesse | durch Job-Prozesslimit 1 ausgeschlossen |

Der Worker wird atomar in einen eigenen Windows-Job aufgenommen. Der Job wird bei
Timeout, Fehler, normalem Rücklauf oder Tod des Elternprozesses geschlossen;
`KILL_ON_JOB_CLOSE` beendet dabei den Worker. Die Überwachung wartet nicht auf einen
hängenden ETW-/TDH-Aufruf. Sie liest nur bereits verfügbare Pipe-Bytes und kontrolliert
die Zeit zwischen den Abfragen. Dies ist keine Echtzeitgarantie gegen einen
blockierten Scheduler; die vorbereitenden Datei- und Prozessstartaufrufe sind
synchrone Windows-Aufrufe und nicht selbst präemptiv unterbrechbar.

Die Prozessüberwachung wird mit dem
[privaten Aufzeichner](ETW_CAPTURE_SUPERVISION.md) geteilt. Ein erfolgreicher
Abbruchaufruf wird intern getrennt vom tatsächlich beobachteten Prozessende
behandelt; das öffentliche ETL-Ergebnisformat bleibt unverändert.

Nur das Pipe-Schreibhandle und ein festes NUL-Handle werden explizit vererbt.
Es gibt keine Shell, kein sichtbares Fenster und keine geerbte Umgebung. Die
vorhandenen VPN-Starts verwenden weiterhin ihren ursprünglichen Pfad ohne
Handle-Vererbung und ohne dieses zusätzliche Speicherlimit. Der interne
Worker-Einstieg prüft die Job-Begrenzungen; ein gewöhnlicher direkter Aufruf wird
abgewiesen. Der Worker hat weiterhin die Rechte desselben Benutzers. Der Job ist
eine Ressourcen- und Lebensdauerbegrenzung, keine Sicherheits-Sandbox gegen
Codeausführung durch eine Schwachstelle in einem nativen Windows-Parser.

## Quellenvertrag

Windows erhält ausschließlich einen Dateinamen, keinen Echtzeit-Loggernamen.
`PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP` bewahrt die
ursprünglichen Ereigniszeiten. Der Bericht nennt den Clock-Typ und die
Performance-Counter-Frequenz aus dem Dateikopf. Sitzungsstart/-ende bleiben separat
als FILETIME-Werte dargestellt; Rohzeitstempel werden nicht als FILETIME oder als
QPC-Zeit ausgegeben, ohne den jeweiligen Clock-Typ zu berücksichtigen.
[Microsoft: EVENT_TRACE_LOGFILEW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew).

Der native `EVENT_RECORD` wird innerhalb seines Callback-Lebens direkt an TDH
übergeben. Nur zur Schemaauswahl wird eine begrenzte Payload-Kopie erstellt;
Header, Descriptor und BufferContext werden für TDH nicht rekonstruiert.
Nicht unterstützte Zusatzdaten, Header, Versionen, Opcodes oder Eigenschaftsgrößen
führen zum Abbruch. Klassische Prozessstart/-ende-/Bestandsereignisse werden für
die zeitliche Korrelation ausgewertet. Andere Provider werden gezählt und ignoriert.

Aus dem durch `OpenTraceW` bereitgestellten `TRACE_LOGFILE_HEADER` werden
`EventsLost` und `BuffersLost` übernommen. Das gleichnamige Feld
`EVENT_TRACE_LOGFILEW.EventsLost` ist unbenutzt und wird nicht ausgewertet.
Fehlender Abschluss (`EndTime == 0`), unplausible Zeit-/Pointer-/Clock-Metadaten
oder gemeldete Verluste verhindern die Ereignisverarbeitung.
[Microsoft: TRACE_LOGFILE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header).

Zirkuläre, angehängte und in mehrere Dateien aufgeteilte Aufzeichnungen werden
abgewiesen. Die sequenziellen Modi 0 und 1 werden unterstützt.
[Microsoft: Logging Mode Constants](https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants).
Ein klassischer LostEvent-Marker wird ebenfalls als Verlust gewertet, nicht als
irrelevanter Provider. Seine Task-GUID ist mit Microsofts
[TraceEvent-Parser](https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs)
abgeglichen. Rückläufige Zeiten ausgewählter Netzwerkereignisse führen zum Abbruch;
die Eingabe wird nicht nachträglich umsortiert.

Diese Angaben stammen aus einer importierten Datei. Weder ein erfolgreicher
`ProcessTrace`-Rücklauf noch Nullwerte in Verlustzählern beweisen deren Authentizität,
aktivierte Provider, lückenlose Historie oder vollständigen Verkehr. Es werden
keine erfundenen Anfangs-/Endzähler für das bestehende JSON-Replay erzeugt.
Der Bericht hat einen eigenen Vertrag mit `source = unverified_etl_file`.
`trace_authenticity_verified`, `loss_completeness_verified`,
`process_identity_verified`, `coverage_verified`, `application_byte_counts_verified`,
`attempt_outcomes_available`, `baseline_compatible` und `enforcement_active` sind
immer `false`. Diese Felder setzt ausschließlich der Elternprozess; sie sind
nicht Teil der deserialisierbaren Worker-Nachricht.

## Validierung und verbleibende Arbeit

Die neuen Prüfungen umfassen Header-/Verlustfehler, getrennte Zählung,
Zeitregression, native TDH-Verarbeitung eines synthetischen Callback-Datensatzes,
Callback-Grenzen und LostEvent. Echte Kindprozesse prüfen Timeout mit beobachtetem
Prozessende, Ausgabeüberlauf, Absturz, vollständiges Auslesen und die per Windows
zurückgelesenen Job-Limits. Die Eingabesperre verhindert im Test Schreiben und
Löschen. Die interne Pipe-Nachricht weist unbekannte/doppelte Felder, abgeschnittenes
JSON, unmögliche Zähler und eingeschleuste Berechtigungsfelder ab.

Ein Integrationstest erzeugt eine kleine echte ETL-Datei mit
`PRIVATE_LOGGER_MODE | PRIVATE_IN_PROC`. Ausschließlich ein eigenes synthetisches
User-Mode-Testereignis wird geschrieben; kein Kernel-/Netzwerkprovider wird aktiviert.
Die Sitzung wird sofort beendet und zusätzlich durch einen Drop-Guard abgesichert.
Das produktive Programm enthält diesen Controller-Code nicht.
[Microsoft: private Sitzung](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-private-logger-session).
Das gebaute CLI liest die Datei im Worker vollständig und meldet korrekt
`no_supported_network_events`. Eine abgeschnittene Variante und beliebige ungültige
Bytes ergeben ebenfalls keine erfolgreiche Netzwerkbeobachtung.

**Noch nicht nachgewiesen:** die vollständige Kette mit einer echten Kernel-
Netzwerkaufzeichnung, Offloading-/Byte-Semantik, IPv6 an realen Interfaces,
absichtlich erzeugte reale ETW-Verluste und die Zuordnung historischer PIDs zu
Prozessinkarnationen. Die synthetischen TDH-Tests und die private ETL-Datei ersetzen
diese Abnahme nicht. Eine isolierte Windows-Testumgebung fehlt weiterhin.

Die zeitliche Prozessstart/-ende-/Rundown-Zuordnung mit expliziten Lücken und
PID-Wiederverwendung ist als [Diagnose implementiert](ETL_PROCESS_CORRELATION.md).
Eine aktuelle `OpenProcess`-Abfrage darf keine historische Identität nachträglich
bestätigen. Erst belastbare
Prozessidentität und Quellenvollständigkeit erlauben die Anbindung an die
Verhaltensanalyse. WFP-Durchsetzung bleibt gesondert offen;
`OPENVPN_NOT_READY` gilt unverändert.

Lokale Prüfprotokolle: `target/restart-audit/etl-*`.

**Stand bei Einführung des ETL-Lesers:** 1.498 Windows-Workspace-Tests bestanden, 0 fehlgeschlagen,
1 bereits zuvor ignorierter Generator; 146 Testsuiten. Dieser Schritt ergänzt
20 Prüfungen (16 Modulprüfungen einschließlich Testprozess-Einstieg und vier
CLI-Integrationsprüfungen). Windows-Workspace-Build und Clippy für alle Targets mit
`-D warnings`, Linux-Clippy für alle `ssk-winhost`-Targets sowie Format-, Diff- und
lokale Dokumentationslinkprüfung bestehen. Linux-Tests wurden nicht ausgeführt.
Die Tests benötigen außerhalb der Sandbox lesenden WMI-/ACL-Zugriff; Systemeinstellungen
wurden dafür nicht geändert. Die 17 Workspace-Abhängigkeiten des Daemons bleiben
unverändert. Zusätzlich aktiviert wurde nur `Win32_System_Time` der bereits
gepinnten `windows-sys`-Version.
