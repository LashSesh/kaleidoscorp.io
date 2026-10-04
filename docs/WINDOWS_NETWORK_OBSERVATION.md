# Windows-Beobachtung für die Netzwerk-Membran

Stand: 22. September 2026. Implementiert ist eine separate, rein lesende
Prozessdiagnose: `ssk-winhost::network_snapshot` und `ssk-netobserve`. Sie ergänzt
die [Offline-Analyse](NETWORK_ANALYSIS_BASELINE.md), ist aber noch keine
Ereignisquelle für deren Verbindungsraten oder Byte-Zähler. Der Daemon und der
privilegierte Broker rufen sie nicht auf.

## Ausführen

Im Repository-Verzeichnis unter Windows:

```powershell
cargo run -p ssk-winhost --bin ssk-netobserve --offline --locked -- snapshot --self
cargo run -p ssk-winhost --bin ssk-netobserve --offline --locked -- snapshot --pid $PID
```

`--self` untersucht den Diagnoseprozess; dessen Tabellen können leer sein.
`--pid $PID` untersucht die aufrufende PowerShell. Eine andere dezimale PID wählt
einen anderen Prozess aus, soweit dessen Zugriffsrechte das erlauben. Der Prozess
wird zum Zeitpunkt von `OpenProcess` aufgelöst: Dies bestätigt keine zuvor aus
einer fremden Ereignisquelle übernommene PID. Es werden keine zusätzlichen Rechte
aktiviert. Bei verweigertem Zugriff erscheint ein Fehler.

Das Werkzeug liest vier Tabellen nacheinander: TCP/IPv4, TCP/IPv6, UDP/IPv4 und
UDP/IPv6. Windows liefert die systemweiten Tabellen; nur Zeilen der gewählten PID
werden im Bericht behalten. Rohpuffer werden anschließend verworfen. Der Bericht
enthält lokale Endpunkte und gegebenenfalls Gegenstellen, aber keine Paketinhalte,
Programmpfade oder Benutzerkennungen. Er wird als JSON auf stdout ausgegeben;
es wird kein Erfassungsdienst installiert und kein Bericht automatisch gespeichert.

Exitcode 0 heißt **Diagnosebericht erzeugt**. Jede Tabelle hat zusätzlich
`observed` oder `unavailable` mit einem Fehlergrund. Ein Bericht mit fehlgeschlagener
Tabelle erhält `all_tables_read: false`. Exitcode 2 steht für unzulässige Argumente
oder eine insgesamt nicht mögliche Aufnahme, beispielsweise wegen Prozessende.
Auf anderen Plattformen liefert die API `UnsupportedPlatform`, keine leere
Erfolgsliste. `--help` funktioniert unabhängig von der Plattform.

## Nachweise und ihre Grenzen

Vor dem ersten Tabellenaufruf öffnet die Implementierung einen nicht vererbbaren
Prozesshandle ausschließlich mit `PROCESS_QUERY_LIMITED_INFORMATION` und
`SYNCHRONIZE`. Erstellung und Lebenszustand werden über diesen einen Handle gelesen.
Nach den Tabellen wird derselbe Handle erneut auf Prozessende geprüft. Endet der
Prozess bis dahin oder schlägt die Prüfung fehl, wird der gesamte Bericht verworfen.
Es gibt keinen zweiten `OpenProcess`-Aufruf zur nachträglichen Zuordnung.

Dadurch wird ein während der Aufnahme endender Prozess nicht über seine womöglich
neu vergebene PID mit einem Nachfolger verwechselt. Der Bericht nennt die PID und
die Erstellungszeit als dezimale FILETIME-Zeichenkette, damit JSON-Verbraucher mit
Fließkommazahlen deren Genauigkeit nicht verlieren. Die zufällige `capture_id`
unterscheidet Aufnahmen, ist aber kein Beweis für Rechneridentität oder Authentizität.

Das Ergebnis beschreibt die PID-Zuordnung der IP-Helper-Tabellen während dieser
Abfrage. Es beweist weder, welcher Code in einem Prozess ausgeführt wird, noch den
Urheber einzelner Pakete. Geerbte/geteilte Sockets, Proxys und bereits beendete
Verbindungen benötigen weitergehende Zuordnungsregeln. Die Erstellungszeit ist
keine Prozesssignatur, und der Bericht authentifiziert keine importierte Datei.

Microsoft dokumentiert die nötigen Abfragerechte und Zeitwerte bei
[GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
die handlebasierte Öffnung bei
[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
und die nicht blockierende Zustandsprüfung mit Timeout 0 bei
[WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject).
Die Abfolge vor/nach den Tabellen ist unsere daraus abgeleitete Diagnosegrenze.
Die unterschiedliche Lebensdauer von PID und Handle ist unter
[Process Handles and Identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)
beschrieben.

## Was die Quelle tatsächlich messen kann

| Information | Stand |
|---|---|
| Lokaler Endpunkt, TCP/UDP, IPv4/IPv6 | Aus der jeweiligen OWNER_PID-Tabelle, nur für die ausgewählte PID |
| TCP-Gegenstelle und TCP-Zustand | Roher MIB-Zustand; bei LISTEN bleibt die Gegenstelle `null` |
| UDP-Gegenstelle | Nicht geliefert; bleibt `null`, auch bei einem verbundenen UDP-Socket |
| Prozessinkarnation während der Abfrage | Gehaltener Handle, Erstellungszeit und Lebensprüfung vor/nach den Tabellen |
| Zeitbasis | Monotone Dauer relativ zum Beginn dieser Aufnahme, zusätzlich je Tabellenabfrage |
| Abgeschlossene Verbindungsversuche, Fehlerrate | Nicht verfügbar |
| Übertragene Bytes, Nutzdaten, Retransmissionen | Nicht verfügbar |
| Ereignisverlust oder kurzlebige Verbindungen zwischen Abfragen | Nicht messbar |
| Vollständiges gemeinsames Zeitfenster | Nicht vorhanden: vier aufeinanderfolgende Tabellenabfragen |
| Firewall-/VPN-Durchsetzung | Nicht vorhanden |

Die Semantik folgt den APIs
[GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
und [GetExtendedUdpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable).
IPv6-Adressen und Scope-IDs bleiben erhalten; die Parser folgen den dokumentierten
Byteordnungen von
[MIB_TCP6ROW_OWNER_PID](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcp6row_owner_pid)
und [MIB_UDP6ROW_OWNER_PID](https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6row_owner_pid).

Jeder Bericht enthält deshalb fest:

```json
{
  "connection_history_complete": false,
  "attempt_outcomes_available": false,
  "byte_counts_available": false,
  "event_loss_observable": false,
  "baseline_compatible": false,
  "enforcement_active": false
}
```

Es gibt keine Umwandlung in `ssk-netanalysis::Observation`. Wiederholt sichtbare
Tabellenzeilen sind keine neuen Verbindungsversuche. Eine leere Tabelle bedeutet
keinen erfolgreichen Verkehr und rechtfertigt keine Freigabe. Der bestehende
IPv4-`WindowsConnectionSource` bleibt separat; seine toleranten Parser und seine
grobe HTTP-ähnliche Zustandsabbildung werden für diese Diagnose nicht verwendet.

## Begrenzung und Fehlerverhalten

- Höchstens vier native Aufrufe pro Tabelle einschließlich Größenabfrage. Wächst
  die Tabelle fortlaufend, endet die Abfrage mit `UnstableTable`.
- Höchstens 1 MiB Rohdaten pro Tabelle, mit auf vier Bytes ausgerichtetem Puffer.
  Eine begrenzte Parsing-Kopie bzw. Ersatzallokation kann vorübergehend zusätzlich
  bis zu 1 MiB belegen; hinzu kommen die behaltenen Endpunktzeilen.
- Höchstens 16.384 Tabellenzeilen pro Tabelle werden geprüft. Höchstens 1.024
  passende Zeilen pro Tabelle, insgesamt maximal 4.096, gelangen in den Bericht.
  Eine Überschreitung verwirft die betroffene Tabelle vollständig.
- Fehlende Header, abgeschnittene Zeilen und widersprüchliche Längen werden als
  Fehler ausgegeben; ein gültiger Präfix wird nicht als vollständige Tabelle gezeigt.
- Zwei Sekunden Gesamtbudget, geprüft zwischen synchronen OS-Aufrufen und vor
  Veröffentlichung. Das ist **kein harter Abbruch** eines im Betriebssystem
  blockierten Aufrufs. Ein verspätet zurückkehrender Aufruf ergibt keinen Bericht.
- Auf Prozessende folgt ein Gesamtfehler. Einzelne Tabellenfehler bleiben dagegen
  im Diagnosebericht sichtbar, zusammen mit den unabhängig gelesenen Tabellen.
- Prozesshandle und Puffer werden auf allen Rückwegen freigegeben. Es werden keine
  Prozesse gestoppt, Firewallregeln angelegt oder VPN-/Dienstzustände geändert.

## Vertrag für die spätere Ereignisquelle

Die folgende Schnittstelle ist noch **nicht implementiert**. Sie beschreibt, welche
Nachweise vor einer Kopplung an die Verhaltensanalyse fehlen:

1. **Sitzung und Herkunft:** kontrollierte Quelle, neuer Sitzungsbezeichner nach
   Neustart, feste Provider-/Schemazuordnung und klare Aussage zum beobachteten
   Verkehr. Importierte JSON-Dateien bleiben unbestätigt.
2. **Prozess- und Flusszuordnung:** Prozessinkarnation zum Ereigniszeitpunkt,
   Flussgeneration und genaue Endpunkte. Eine später geöffnete PID genügt nicht.
   Fehlende, verspätete und widersprüchliche Zuordnung muss unbekannt bleiben.
3. **Merkmalssemantik:** abgeschlossene Versuche genau einmal zählen; festlegen,
   welche Fehler und welche Byte-Schicht gemeint sind. Deltas dürfen nicht mit
   kumulativen Zählern verwechselt werden. UDP benötigt einen eigenen Vertrag.
4. **Zeit und Verlust:** monotone Quellzeit, definierte Umordnung, erkennbare Lücken,
   Provider-/Pufferverluste und Neustarts. Eigene fortlaufende Nummern allein
   beweisen nicht, dass vor ihrer Vergabe keine Ereignisse verloren gingen.
5. **Fensterabschluss:** Veröffentlichung erst nach nachvollziehbarem Abschluss;
   verspätete Ereignisse oder Verlustmeldungen müssen bereits publizierte
   Bewertungen ungültig machen können. Keine stillschweigende Weiterverwendung.
6. **Lastgrenzen:** begrenzte Warteschlangen, Scopes, Speicher und Rechenarbeit;
   Überlast erzeugt einen sichtbaren Ausfallzustand. Zusätzlich braucht der Dienst
   einen beaufsichtigten Abbruch-/Neustartpfad für hängende Quellen.

ETW ist ein Kandidat für die Ereignisdiagnose. Microsoft beschreibt dort ausdrücklich
Puffer- und Ereignisverluste; seine Verwendung allein wäre deshalb kein
Vollständigkeitsnachweis.
[Microsoft: About Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing).
Als nächster Schritt sind geeignete Netzwerk- und Prozessprovider mit ihren
tatsächlichen Ereignisfeldern, Verlustsignalen und Berechtigungen zu prüfen.
Es wird hier weder eine ETW-Sitzung gestartet noch ein Provider aktiviert.

Die [ETW-Quellenprüfung und der erste TDH-Decoder](ETW_NETWORK_DECODER.md) sind
inzwischen als separater Offline-Baustein umgesetzt. Der
[überwachte ETL-Dateileser](ETL_NETWORK_READER.md) ergänzt den Empfang aus vorhandenen
Dateien. Eine [zeitliche Prozesszuordnung](ETL_PROCESS_CORRELATION.md) ist als
Diagnose ergänzt. Live-Empfang, nachgewiesene Quellenvollständigkeit und die Abnahme
der Prozessidentität an echten Kernel-Aufzeichnungen bleiben offen.

WFP bleibt der gesonderte Durchsetzungsweg. Analyse und Beobachtung können bestehende
Policy-Sperren oder VPN-Vorgaben nicht überstimmen. Die isolierte Windows-Abnahme
bleibt erforderlich; eine Testumgebung steht weiterhin nicht zur Verfügung.

## Validierung dieses Schritts

20 neue Windows-Prüfungen bestehen: 17 Modulprüfungen und drei Integrationsprüfungen.
Neben Parser-, Größen-, Wiederholungs- und Zeitgrenzen werden Prozessende vor/nach
den Tabellen, unzulässige Prozessidentität und unabhängige Tabellenfehler geprüft.
Die reinen Prüfungen injizieren diese Fehler; sie behaupten keinen real erzwungenen
PID-Recycling-Angriff. ABI-Größen und Tabellen-/PID-Offsets werden mit den gepinnten
Windows-Strukturen verglichen.

Ein echter Windows-Test öffnet TCP-Listener und UDP-Sockets auf IPv4-/IPv6-Loopback
sowie eine lokale TCP-Verbindung und findet deren Endpunkte und Zustände in den
OS-Tabellen. Ein zweiter Test startet das Diagnoseprogramm und prüft dessen JSON.
Der direkte `--self`-Probelauf las ebenfalls alle vier Tabellen. Sein Bericht wurde
vom bestehenden Analyse-Replay wie erwartet mit Exitcode 2 abgewiesen.
Nicht getestet sind IPv6-Scope-IDs ungleich null an realen Interfaces, LocalSystem,
geschützte Fremdprozesse oder anhaltende Angriffslast; Scope-Byteordnung wird bisher
gegen dokumentierte synthetische Daten geprüft.

Die vollständige Windows-Workspace-Suite besteht mit **1.450 bestandenen Tests,
0 Fehlern und 1 bereits zuvor ignorierten Generator**. Windows-Build und
Workspace-Clippy für alle Targets mit `-D warnings`, Linux-Clippy für alle Targets
von `ssk-winhost`, Format-, Diff- und lokale Linkprüfung bestehen. Linux-Tests wurden
hier nicht ausgeführt. Es kamen keine Abhängigkeiten hinzu; der Daemon behält seine
17 Workspace-Abhängigkeiten.

Lokale Protokolle: `target/restart-audit/network-source-*`.
Der lokale Diagnosebericht liegt unter
`target/restart-audit/network-source-self-report.json`. Er ist weder ein
Durchsetzungsnachweis noch eine signierte, extern beglaubigte Aufzeichnung.
