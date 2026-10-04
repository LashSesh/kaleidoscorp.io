# Privater Aufzeichner und lokale Netzwerk-Testlast

Stand: 22. September 2026. `ssk-netcapture` bietet eine ausführbare private
ETW-Abnahme und eine feste Loopback-Testlast. Die systemweite Prozess-/Netzwerk-
aufzeichnung ist weiterhin nicht startbar. `ssk-netobserve` bleibt der
[lesende Diagnosebefehl](ETL_NETWORK_READER.md).
Der private Aufzeichner läuft jetzt unter einer
[separaten Prozessüberwachung](ETW_CAPTURE_SUPERVISION.md).

## Ausführbare Befehle

```powershell
cargo run -p ssk-winhost --bin ssk-netcapture -- plan
cargo run -p ssk-winhost --bin ssk-netcapture -- private-fixture C:\Traces\private-test
cargo run -p ssk-winhost --bin ssk-netobserve -- etl-check C:\Traces\private-test\recording.etl C:\Traces\private-test\closure.json
cargo run -p ssk-winhost --bin ssk-netcapture -- traffic
```

Für `private-fixture` muss der Elternordner existieren, der Zielordner dagegen
neu sein. Der Befehl beansprucht ihn mit einer einzelnen `create_dir`-Operation.
Vorhandene Verzeichnisse, UNC-/Geräte-/Stream-Pfade und erkannte Reparse-Punkte in
den Vorfahren werden abgewiesen. Er repariert keine vorhandenen Ordner und löscht
keine Beweisdaten. Bei Fehlern bleiben bereits geschriebene Artefakte erhalten;
ein neuer Versuch benötigt einen neuen Ordner.

| Befehl | Wirkung |
| --- | --- |
| `plan` | Gibt das geplante Systemprofil, fünf Sekunden / 16 MiB als vorgeschlagene Grenzen und die fehlenden Voraussetzungen aus; rein lesend |
| `private-fixture` | Erzeugt acht synthetische Ereignisse im eigenen Hilfsprozess und schreibt `recording.etl`, `controller.json`, `closure.json`, `supervision.json` |
| `traffic` | Führt acht Anfrage-/Antwortpaare mit je 128 Bytes für jeden der vier Fälle TCP/UDP × IPv4/IPv6 aus |

`record`, `system`, beliebige Zieladressen, Provider, Flags und Zusatzargumente
sind keine CLI-Fähigkeiten. Beide aktiven Befehle sind explizit von `plan` und
den Lesebefehlen getrennt. Es gibt keinen Aufrufpfad aus Daemon oder Broker.

Exitcode 0 bedeutet, dass JSON erzeugt wurde; dessen `status` bleibt maßgeblich.
Exitcode 2 bezeichnet ungültige Argumente, Datei- oder Aufzeichnungsfehler.
`traffic` kann also mit Exitcode 0 einen Bericht mit `status=unavailable` liefern.

## Sitzungssteuerung

Der interne Steuerungskern trennt native Aufrufe von den Lebensdauer- und
Fehlerregeln. Besitz entsteht ausschließlich durch einen erfolgreichen eigenen
Start. Bei `ERROR_ALREADY_EXISTS` oder einem anderen Startfehler wird weder eine
Sitzung übernommen noch nach ihrem Namen gestoppt. Die native Umsetzung hat
ausschließlich `PRIVATE_LOGGER_MODE | PRIVATE_IN_PROC | FILE_MODE_SEQUENTIAL`.
Der feste beschreibende Sitzungsname ist `ScorpioSync.PrivateCaptureAcceptance`;
jeder Durchlauf registriert eine eigene zufällige Provider-GUID.

Die Folge ist Start → eigenen Provider aktivieren → erste Abfrage → achtmal
Ereignis einreichen und Statistik abfragen → Identität erneut abfragen → Stopp.
Die jeweils erste erkannte
Störung bleibt erhalten. Fehler beim Aktivieren/Einreichen, fehlende Statistiken,
abweichende GUID/Modi/Flags, Verluste, rückläufige Pufferzähler oder überschrittene
Zeitbudgets führen zu `unavailable`. Ein abschließender Stopp erfolgt nur nach
erneut passender Sitzungs-GUID; bei fremder oder unbekannter Identität bleibt er
aus. Ein Rust-Drop-Guard ergänzt die Bereinigung bei Unwinding.

Für `QUERY` und `STOP` entstehen frische, ausgerichtete und genullte native
Eigenschaftspuffer mit Platz für beide Namen. Gesteuert wird nur über das zuvor
erhaltene Handle. `ERROR_MORE_DATA` beim Stopp bedeutet keinen erfolgreichen
Statistikabschluss, obwohl die Sitzung bereits beendet sein kann.
`ERROR_WMI_INSTANCE_NOT_FOUND` führt ebenfalls zur Aufgabe des Handles. Bei
anderen Stoppfehlern oder unklarer Identität wird ein weiterer Bereinigungsversuch
mit erneuter Identitätsprüfung explizit protokolliert. Ein späterer Erfolg wandelt
den bereits fehlgeschlagenen Bericht nicht in Erfolg um.
[Microsoft: ControlTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew).

Die Dateigrenze ist nativ auf 1 MiB gesetzt; nach dem Schließen wird die tatsächliche
Größe nochmals geprüft. Angefordert werden zwei Puffer à 64 KiB und ein
Flush-Intervall von einer Sekunde. `events_submitted` zählt erfolgreiche
`EventWrite`-Rückgaben, nicht bewiesene einzelne Ereignisse in der Datei. Die
Abnahme liest die Windows-Datei zusätzlich mit dem bestehenden ETL-Leser.

**Das innere Zeitbudget ist kooperativ:** Eine Sekunde wird zwischen den Aufrufen
und nach dem Stopp geprüft. Ordneranlage, Registrierung und Datei-/Hashausgabe
liegen außerhalb dieses inneren Budgets. `native_calls_preemptible=false` bleibt
zutreffend für einzelne native Aufrufe. Zusätzlich überwacht der Elternprozess
den gesamten Worker mit fünf Sekunden und kann dessen Job beenden, auch wenn ein
Aufruf hängt. Danach beobachtet er höchstens eine weitere Sekunde das Prozessende.
Synchrone Elternprozess-Aufrufe und Scheduler-Verzögerungen bleiben Grenzen.

## Artefakte und Aussagekraft

`controller.json` verwendet Schema 2 und enthält Startstatus, erste Abfrage,
Identitätsabfrage vor dem Stopp, Bereinigungsstatus, gegebenenfalls den ersten
Stopp-Rücklauf und einen weiteren Bereinigungsversuch, Anzahl der Abfragen/
eingereichten Ereignisse, Zeit und den ersten Fehler. Ein unterbliebener Stopp
bleibt `null`. `supervision.json` (Schema 1) ergänzt unabhängig davon die vom
Elternprozess beobachtete Prozesslebensdauer. Nur nach störungsfreiem Abschluss
wird die geschlossene Datei ohne
Schreib-/Löschfreigabe geöffnet, gehasht und `closure.json` erzeugt. JSON-Dateien
werden mit `create_new` angelegt und synchronisiert.

Der [Abschlussvertrag](ETL_RECORDING_CLOSURE.md) verwendet dieselben strikten
Statistiktypen wie der Controller. Der private Bericht ist `synthetic_fixture`
und beschreibt ehrlich private Flags ohne Kernel-/Netzwerkprovider. Daher muss
`etl-check` trotz passender Prüfsumme folgende Gründe liefern:

```json
["unsupported_profile_configuration", "etl_unavailable"]
```

Das ist die erwartete Abnahme: Die echte Windows-Datei ist lesbar, wird aber nicht
als System-Netzwerkaufzeichnung ausgegeben. Alle Vertrauens-/Durchsetzungsfelder
bleiben falsch. Die aktuellen Testartefakte erben die Rechte ihres Elternordners;
sie sind kein gegen einen angreifergesteuerten Dateisystem-Namensraum gehärteter
Speicher für sensible Systemaufzeichnungen.

## Loopback-Testlast

`traffic` verwendet ausschließlich `127.0.0.1` und `::1` mit dynamischen lokalen
Ports, keine DNS-Auflösung und keine externen Ziele. Pro Fall werden acht
128-Byte-Nachrichten übertragen und zurückgesendet. Jede Nachricht enthält ihre
Ordinalnummer; beide Richtungen werden vollständig verglichen. UDP prüft auch
die Datagrammlänge und verbindet beide Sockets mit ihrem jeweiligen Gegenüber.
TCP überprüft den akzeptierten Peer gegen den eigenen Client.

Jeder Fall meldet abgeschlossene Rundläufe und die dabei beidseitig verifizierten
Anwendungsbytes: im Erfolgsfall 2.048 Bytes pro Fall, 8.192 Bytes insgesamt.
Das sind keine ETW- oder Drahtzähler. Fehlendes IPv6, Zeitüberschreitungen und
sonstige Fehler bleiben `unavailable`, statt als übersprungene Erfolge zu gelten.
Die vier Fälle teilen sich ein kooperatives Drei-Sekunden-Budget; Socket-I/O hat
zusätzliche Zeitlimits von 250 ms. Es gibt keine Echtzeitgarantie bei blockierendem
Betriebssystem oder Scheduler. Alle Sockets gehören dem Aufruf und werden beim
Verlassen ihres Gültigkeitsbereichs geschlossen.

Der Bericht nennt die PID des Testprozesses, die Sollgröße und einzelne Ergebnisse.
Er bestätigt weder die Erfassung dieses Verkehrs durch ETW noch Schutzwirkung.
Die private Aufnahme erfasst den Loopback-Verkehr nicht. In der künftigen VM kann
`traffic` als separater Prozess innerhalb einer Systemaufnahme gestartet werden,
um dessen Start, Verkehr und Ende zu korrelieren. Der zusätzliche Fall eines
bereits vor der Aufnahme lebenden Prozesses ist noch vorzubereiten.

## Warum der Systemstart noch fehlt

Microsoft dokumentiert, dass eine Sitzung bis zum expliziten Stopp, Neustart,
I/O-Fehler oder Erreichen der nichtzirkulären Dateigrenze aktiv bleiben kann.
Ein Rust-Drop-Guard garantiert bei hartem Prozessabbruch keine Aufräumaktion.
Systemweite Logger müssen deshalb eine zusätzliche Überwachung und sichere
Wiederaufnahme-/Bereinigungsregeln erhalten, bevor ein Startbefehl angeboten wird.
Die kleinste sinnvolle Aufzeichnungsreichweite wird auch von Microsoft empfohlen.
[Microsoft: StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew).

Die Prozessüberwachung des privaten Aufzeichners ist implementiert. Noch offen
sind die Wiederherstellung systemweiter Sitzungen, eindeutiger Besitz über
Neustarts hinweg, ein geschützter Ausgabespeicher und die
[isolierte Windows-Abnahme](ETL_RECORDING_CLOSURE.md). `plan` nennt diese Grenzen
mit `system_capture_available=false`. Ein passender Plan ist keine Freigabe.
OpenVPN-Bereitschaft und aktive Membran-/WFP-Durchsetzung bleiben davon getrennt.
