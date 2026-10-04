# Prozessüberwachung des privaten Aufzeichners

Stand: 22. September 2026. `ssk-netcapture private-fixture <new-directory>`
führt den privaten Aufzeichner in einem überwachten Hilfsprozess aus. Der
Elternprozess überwacht dessen Laufzeit, Ausgabe und Prozessende. Systemweite
Prozess-/Netzwerkaufzeichnung ist weiterhin nicht startbar.
[Bedienung und Testlast](ETW_CAPTURE_PREPARATION.md).

## Grenzen und Lebensdauer

| Grenze | Wert / Verhalten |
| --- | --- |
| Worker-Deadline | 5 Sekunden, vom Elternprozess überwacht |
| Beobachtung nach Abbruch | zusätzlich höchstens 1 Sekunde auf Prozessende warten |
| Privater zugesicherter Speicher | 256 MiB über Windows-Job-Limit |
| Prozesse im Job | einer; keine Nachfolgeprozesse oder Breakaway-Freigabe |
| Worker-Nachricht | höchstens 4 KiB; Schema 1 und genau acht eingereichte Ereignisse |
| Native Aufnahme | acht synthetische Ereignisse, 1 MiB, inneres kooperatives Ein-Sekunden-Budget |
| Artefakte bei Erfolg | `recording.etl`, `controller.json`, `closure.json`, `supervision.json` |

Der Start ordnet den Worker atomar über `PROC_THREAD_ATTRIBUTE_JOB_LIST` einem
eigenen Job zu. Nur das Pipe-Schreibhandle und ein NUL-Handle werden vererbt;
Job- und Prozesshandles bleiben beim Elternprozess. Es gibt keine Shell,
geerbte Umgebung oder sichtbare Konsole. Der interne Worker-Einstieg prüft die
Job-Grenzen vor dem Dateizugriff. Diese Prüfung ist keine Authentifizierung.

Bei einem Fehler beendet die Überwachung ausschließlich ihren eigenen Job über
das gehaltene Handle. Sie protokolliert den API-Rücklauf und prüft anschließend
das Prozessende. `KILL_ON_JOB_CLOSE` dient auch beim Tod des Elternprozesses als
Rückfall. Microsoft beschreibt die Beendigung beim Schließen des letzten
Job-Handles und die Wirkung von `TerminateJobObject` auf zugeordnete Prozesse.
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[TerminateJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject).

Damit muss der Elternprozess nicht auf die Rückkehr eines blockierenden nativen
Aufrufs im Worker warten. Synchrone Datei-/Prozessstartaufrufe im Elternprozess
und ein blockierter Scheduler bleiben Grenzen; die Zeiten sind keine
Echtzeitgarantie. Der Worker läuft mit den Rechten desselben Benutzers. Der Job
begrenzt Ressourcen und Lebensdauer, stellt aber keine Sicherheits-Sandbox dar.
Der Ausgabeordner erbt weiterhin Rechte; Schutz gegen einen feindlich
veränderbaren Dateisystem-Namensraum ist noch nicht implementiert.

Der [ETL-Dateileser](ETL_NETWORK_READER.md) verwendet denselben Überwachungskern.
Seine bisherigen Grenzen von zehn Sekunden, 16 KiB Ausgabe und 256 MiB bleiben
erhalten. Neu ist die zusätzliche begrenzte Beobachtung des Prozessendes nach
Abbruch. Sein Ergebnisformat bleibt Schema 2.

## Getrennte Belege für Prozess und Sitzung

`supervision.json` wird vom Elternprozess mit `create_new` geschrieben und
synchronisiert. Der Bericht verwendet Schema 1:

| Feld | Bedeutung |
| --- | --- |
| `status` | `worker_completed` oder `unavailable` |
| `failure` | Worker-Fehler samt Ursache, ungültiges Protokoll oder fehlende/unzulässige Artefakte |
| `process.started` | Worker wurde gestartet |
| `process.termination_requested` | expliziter Abbruch wurde angefordert |
| `process.termination_call_succeeded` | API-Ergebnis, andernfalls `null` |
| `process.exit_observed` / `exit_code` | tatsächlich beobachtetes Prozessende und dessen Code |
| `worker_completion_accepted` | Exitcode 0, gültige Nachricht und begrenzte vorhandene Artefakte |
| `session_cleanup_verified` | immer `false`; Prozessende beweist keinen sauberen ETW-Abschluss |
| `system_capture_available` / `enforcement_active` | immer `false` |

Die Worker-Nachricht darf keine zusätzlichen Felder oder doppelte Schlüssel
enthalten. Sie kann weder Sitzungsbereinigung noch Schutzwirkung bestätigen.
Nach einem erfolgreichen Rücklauf prüft der Elternprozess die drei erwarteten
Dateien auf reguläre Dateien ohne Reparse-Punkte und auf ihre Größen:
ETL 1 Byte bis 1 MiB, Controller/Abschluss jeweils 1 Byte bis 16 KiB.
Das ist keine Authentifizierung ihrer Inhalte.

Ein erzwungenes Prozessende erzeugt keinen nachträglichen erfolgreichen
Controller-Stopp und keinen erfundenen Abschlussbericht. Stirbt der Elternprozess,
kann auch `supervision.json` fehlen. Fehlende Berichte sind kein Erfolgsbeleg.
Schreibfehler führen zu Exitcode 2; vorhandene Artefakte werden nicht überschrieben.
Der öffentliche Fixture-Bericht verwendet jetzt Schema 2 und nennt zusätzlich
`supervision_file`.

## Identität vor dem Stopp

Der Controller fragt vor jedem Stopp erneut das gehaltene Sitzungshandle ab und
vergleicht die zurückgemeldete GUID mit der beim eigenen Start vergebenen GUID.
Bei fremder oder nicht feststellbarer Identität wird kein Stopp ausgeführt.
Eine bereits verschwundene Sitzung wird als solche protokolliert. Unklare
Abfrage-/Stoppfehler erlauben genau einen explizit protokollierten weiteren
Bereinigungsversuch mit erneuter Identitätsprüfung. Der erste Fehler bleibt erhalten.

`controller.json` verwendet dafür Schema 2: `cleanup_query`, `cleanup_status`
und gegebenenfalls `cleanup_retry` ergänzen die bisherigen Angaben. `stop` ist
`null`, wenn der Stoppaufruf unterblieb. Im normalen Ablauf entstehen zehn Abfragen:
eine Anfangsabfrage, acht Ereignisabfragen und eine Identitätsabfrage vor dem Stopp.
Ein Drop-Guard bleibt für Rust-Unwinding bestehen; nach dem protokollierten
Wiederholungsversuch folgt kein versteckter dritter Versuch.

`ERROR_MORE_DATA` beim Stopp kann eine bereits beendete Sitzung ohne vollständige
Statistiken bedeuten; es bleibt ein fehlgeschlagener Abschluss.
`ERROR_WMI_INSTANCE_NOT_FOUND` wird nicht in einen erfolgreichen Stopp umgedeutet.
[Microsoft: ControlTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew).
Abfrage und Stopp sind keine atomare Operation und belegen keine sichere
Wiederherstellung systemweiter Sitzungen über Prozessneustarts hinweg.

## Abnahme und verbleibende Arbeit

Automatisierte Windows-Tests starten ausschließlich den privaten Logger mit
eigenem synthetischen Provider. Sie prüfen Hängen, harten Worker-Absturz,
Ausgabeüberlauf, ungültige Abschlussnachrichten und den Tod des Elternprozesses
bei bereits aktiver privater Aufnahme. Der letzte Fall beobachtet das Ende des
Workers über ein Prozesshandle. Die Fehlerauslöser existieren nur im Testcode.
Weitere Tests prüfen unbekannte/fremde Sitzungsidentität und getrennte Angaben
für Abbruchanforderung und beobachtetes Prozessende.

`plan` verwendet Schema 2 und meldet auf Windows
`private_capture_worker_supervised=true`. Offen bleiben
`system_session_crash_recovery`, `protected_output_and_recovery` und
`isolated_windows_acceptance`. Systemweite Sitzungen können den Controller
überleben; der private Job-Mechanismus allein löst das nicht.
[Microsoft: StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew).

Als Nächstes sind geschützter Besitz-/Ausgabespeicher und darauf aufbauende
Wiederherstellungsregeln für den künftigen System-Aufzeichner erforderlich.
Die isolierte Windows-Abnahme fehlt weiterhin. Aktive WFP-Durchsetzung und
OpenVPN-Bereitschaft sind unverändert offen; `OPENVPN_NOT_READY` gilt weiterhin.
