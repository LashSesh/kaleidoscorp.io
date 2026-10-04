# Netzwerk-Membran: erste Analysekomponente

Stand: 22. September 2026. Implementiert als `ssk-netanalysis` und als separates
Werkzeug `ssk-netanalysis-replay`. Dies ist die erste Umsetzung der
[Thronion-Auswertung](THRONION_MEMBRANE_ASSESSMENT_2026-09-22.md).

Die Komponente wertet gespeicherte Beobachtungen aus. Sie erfasst noch keinen
Anwendungsverkehr, bestätigt keine Prozessidentität und verändert keine Netzwerkregeln.
Die vorhandene PolicyEngine, der Broker und der Daemon verwenden sie noch nicht.
Der Dependency-Test des Daemons verhindert eine unbeabsichtigte Einbindung.

Eine separate [Windows-Prozessdiagnose](WINDOWS_NETWORK_OBSERVATION.md) liest
inzwischen TCP-/UDP-Endpunkte über IPv4 und IPv6. Sie liefert noch keine
Verbindungsereignisse oder Byte-Deltas und wird deshalb nicht in diese Baseline
eingespeist.

## Auswertung ausprobieren

Im Repository-Verzeichnis:

```powershell
cargo run -p ssk-netanalysis --bin ssk-netanalysis-replay --offline --locked -- docs/examples/netanalysis-baseline.json
```

Das [Beispiel](examples/netanalysis-baseline.json) enthält ausschließlich synthetische
Daten. Es meldet vier Auffälligkeiten: Verbindungsrate, Fehlerquote, gesendete Datenrate
und Verhältnis zwischen gesendeten und empfangenen Bytes überschreiten die eingestellten
Beispielgrenzen. Das Werkzeug baut keine Verbindung zur im Beispiel genannten Adresse auf.

Das Ausgabeformat enthält unter anderem:

```json
{
  "advisory_only": true,
  "identity_verified": false,
  "coverage_verified": false,
  "enforcement_active": false,
  "verdict": {
    "status": "suspicious",
    "findings": [
      "attempt_rate_exceeded",
      "failure_ratio_exceeded",
      "sent_rate_exceeded",
      "sent_received_imbalance"
    ]
  }
}
```

Dies ist ein gekürzter Auszug. Der vollständige Bericht enthält zusätzlich Scope,
Herkunft, Zeitfenster, Zähler, Baseline-Parameter und deren Versionskennung.
Exitcode 0 bedeutet „Bericht erzeugt“, auch bei `suspicious` oder `unavailable`.
Exitcode 2 bezeichnet unzulässige Eingaben oder einen Ein-/Ausgabefehler. Es gibt
keinen Schalter zum Freigeben, Sperren, Installieren oder Lernen.

## Bedeutung der drei Ergebnisse

| Ergebnis | Aussage |
|---|---|
| `no_anomaly_observed` | Keine der vier konfigurierten Grenzen wurde in den auswertbaren Eingabedaten überschritten. Keine Aussage „schadfrei“ oder „Verbindung erlaubt“. |
| `suspicious` | Mindestens eine Grenze wurde überschritten; die konkreten Kriterien werden genannt. Auch legitime Updates, Backups oder Störungen können dies verursachen. |
| `unavailable` | Das Fenster lässt sich nicht verlässlich nach diesen Regeln auswerten. Ein maschinenlesbarer Grund ersetzt die Bewertung. |

Es gibt keinen künstlichen Gesamtscore und keine angebliche Angriffswahrscheinlichkeit.
Ein konfiguriertes Grenzwertmodell wurde umgesetzt, keine trainierte Malware-Erkennung.
Sämtliche Beispiel- und Standardwerte müssen vor einem Einsatz anhand repräsentativer
Daten und Fehlalarmkosten überprüft werden.

## Eingabe- und Zeitvertrag

Ein Scope bindet **Quell-Epoche, Prozess-/Anwendungsbezeichner, genaue IP/Port-Kombination
und TCP oder UDP**. Dieselben Werte müssen in jedem Ereignis vorkommen. Die Epoche soll
bei einem Neustart der Quelle wechseln; der Subjektbezeichner soll Prozessinkarnationen
unterscheiden. Diese Zeichenketten werden lediglich verglichen. Sie sind keine vom
Betriebssystem bestätigten Identitäten, und gleiche Zeichenketten beweisen keine gleiche
Anwendung. DNS-Namen, VPN-Wege und Benutzeridentitäten sind noch nicht Teil dieses Schemas.

Beide Herkunftswerte, `synthetic_replay` und `unverified_observation`, bleiben für
Durchsetzung unzureichend. Eine Eingabe kann keinen Wert wie `trusted` oder `verified`
behaupten. Die feste Ausgabe `coverage_verified: false` verhindert auch, dass eine
vollständige Sequenz als Beweis einer vollständigen Windows-Erfassung erscheint.

Die Zeitwerte sind ganze Millisekunden derselben logischen, monotonen Quell-Epoche.
Das Fenster ist `[start_ms, start_ms + window_ms)`, also links geschlossen und rechts
offen. Alle Ereignisse liegen darin; gleiche Zeitstempel sind zulässig. Rückwärts
laufende Zeiten und überlaufende Fenstergrenzen werden abgewiesen.

Sequenznummern beginnen beim ausdrücklich angegebenen `first_sequence` und müssen
lückenlos um eins wachsen. Duplikate, Lücken oder Umordnung machen das Fenster dauerhaft
nicht auswertbar. Ebenso wirkt eine Meldung verlorener Ereignisse. Bereits unbekannte
Fenster werden durch spätere gültige Ereignisse nicht wieder gesund; der erste Fehler
bleibt erhalten. Unbemerkte Verluste vor der ersten oder nach der letzten Nummer kann
dieses Verfahren nicht erkennen. Dafür braucht die künftige Quelle einen belastbaren
Vertrag für Vollständigkeit und Fensterabschluss.

Die Signale sind:

- `connection_attempt`: ein abgeschlossenes Verbindungsversuchsergebnis, genau einmal
  mit `failed` gemeldet. Noch offene Versuche und unterschiedliche Fehlerursachen sind
  hier nicht abgebildet.
- `transfer`: neu beobachtete Bytes beider Richtungen relativ zum Subjekt. Es sind
  Differenzen, keine kumulativen Socketzähler. Ein späterer Produzent muss unter anderem
  Nutzdaten-/Leitungsbytes und Retransmissionszählung eindeutig festlegen.

`assess_at_ms` vor dem Fensterende ergibt kein unauffälliges Ergebnis. Die Gültigkeit
endet exklusiv bei `window_end_ms + valid_for_ms`, unabhängig davon, wann der Bericht
erstellt wurde. Ein später ausgestellter Bericht verlängert das Fenster nicht.
Ein leeres oder zu kleines Fenster ist ebenfalls nicht auswertbar.

## Nachvollziehbare Kriterien und Grenzen

| Kriterium | Rechenregel |
|---|---|
| Verbindungsrate | Abgeschlossene Versuche × 1000 > erlaubte Versuche/Sekunde × Fensterdauer in ms |
| Fehlerquote | Ab Mindestanzahl: fehlgeschlagene Versuche × 10.000 > Grenzwert in Basispunkten × abgeschlossene Versuche |
| Gesendete Datenrate | Gesendete Bytes × 1000 > erlaubte Bytes/Sekunde × Fensterdauer in ms |
| Mengenverhältnis | Ab Mindestmenge gesendeter Bytes: gesendete Bytes > erlaubtes Verhältnis × empfangene Bytes |

Genau auf einem oberen Grenzwert entsteht keine Auffälligkeit. Mindestmengen gelten
einschließlich ihres Grenzwerts. Beim Mengenverhältnis mit null empfangenen Bytes bleibt
die Mindestmenge wirksam; es wird nicht durch null dividiert.

Zähler sind `u64`, begrenzte Ereigniszahlen `u32`, die Vergleichsprodukte `u128`.
Dadurch entstehen keine Rundungs-, Logarithmus- oder NaN-Fälle wie in der untersuchten
Thronion-Umrechnung. Zählerüberläufe ergeben einen dauerhaften Fehler. Bei einem Fehler
wird das betreffende Ereignis atomar verworfen: Auch ein bereits berechneter Teilzähler
wird nicht übernommen. Die Ausgabe zeigt dann nur den akzeptierten Präfix, zusammen mit
`unavailable`.

- Fensterdauer: 1–60 Sekunden; anschließende Gültigkeit: 1–60.000 Millisekunden.
- Höchstens 4.096 akzeptierte Ereignisse pro Fenster; ein kleineres Budget ist einstellbar.
- Konstanter Zählerspeicher pro `WindowAnalyzer`, keine Aufbewahrung von Paketen oder
  Ereignislisten; höchstens vier Kriterien pro Bericht.
- Der Replay-Leser liest höchstens 1 MiB plus ein Prüfbyte und akzeptiert höchstens
  4.096 Ereignisse. Unbekannte Felder, doppelte Felder, zusätzliche JSON-Dokumente,
  Fließkommazähler und unbekannte Schemaversionen werden abgewiesen.
- Das Grenzwertmodell ist nach Validierung unveränderlich. Seine Kennung bindet den
  Algorithmusstand und alle zehn Parameter über BLAKE3. Sie ist kein Signaturnachweis.

Die Bibliotheksgrenzen gelten pro Instanz. Ein zukünftiger Dienst muss zusätzlich die
Zahl der Scopes, Warteschlangen, Gesamtspeicher und CPU-Arbeit begrenzen. Das Offline-Tool
verarbeitet genau einen Scope und ein Fenster. Es beweist noch kein angemessenes Verhalten
unter Angriffslast.

## Bericht und spätere Integration

`Assessment` hat private Felder und kann serialisiert, aber nicht deserialisiert werden.
Das schützt die interne Schnittstelle gegen versehentliche Rekonstruktion aus einem
externen Bericht; es ist keine kryptografische Beglaubigung. `snapshot_verdict()` liefert
den historischen Stand. `verdict_for()` prüft vor Wiederverwendung Scope, Baseline und
Zeit erneut. Bereits nicht auswertbare Snapshots werden durch Warten nicht gültig.

`assess()` erstellt einen Snapshot des momentan akzeptierten Präfixes. Bei nachträglich
gemeldetem Verlust wird ein früher ausgegebener Snapshot nicht rückwirkend geändert.
Ein echter Produzent muss daher Fenster vor Veröffentlichung abschließen und spätere
Korrekturen bzw. Widerruf behandeln. Die Eingabedatei und ihre Zeitangaben sind hierfür
ausdrücklich kein Vertrauensnachweis.

Die Komponente enthält weder `PolicyAction` noch `AdmissionToken`, Broker-Aufrufe,
WFP-Zugriffe oder einen Netzwerkclient. Keine Produktkomponente hängt von ihr ab.
Die bestehenden 17 Workspace-Abhängigkeiten des Daemons bleiben unverändert; der
Dependency-Test lehnt `ssk-netanalysis` dort zusätzlich ausdrücklich ab.

Für eine spätere Einbindung gelten die Architekturentscheidungen aus
[ADR 0008](adr/0008-flow-path-owns-the-per-connection-decision.md) und der Thronion-Prüfung:
Die PolicyEngine bleibt zuständig. Eine unauffällige Analyse kann keine feste Sperre,
fehlende Identität, Attestierung oder VPN-Vorgabe überstimmen. Fehlende vorgeschriebene
Evidenz muss zur Verweigerung führen; fehlende optionale Analyse lässt die normalen
Regeln bestehen und wird sichtbar gemeldet. Diese Integration ist noch nicht implementiert.

## Nächster Nachweis

Zuerst den Vertrag einer echten Beobachtungsquelle entwickeln: Betriebssystem-Herkunft,
Prozessinkarnation, Zeitbasis, Verlustmeldungen, Delta-Zähler und abgeschlossene Fenster.
Danach gespeicherte Beobachtungen im Beobachtungsmodus vergleichen und Fehlalarme messen.
Erst auf dieser Grundlage sind Thronion-inspirierte Zusatzverfahren sinnvoll bewertbar.
WFP-Durchsetzung und isolierte Windows-Abnahme bleiben gesonderte notwendige Arbeit.

## Geprüfter Stand

29 neue Prüfungen bestehen: 28 Integrationsprüfungen einschließlich ausgeführtem
Replay-Programm sowie ein Compile-Fail-Vertrag für die nicht deserialisierbare
Auswertung. Geprüft werden Grenzwertübergänge, Mindestmengen, fehlende Beobachtungen,
Zeit- und Sequenzfehler, Scope-Wechsel, Ablauf und Wiederverwendung, Verlustmeldungen,
Speicher-/Ereignisgrenzen, Überläufe und unzulässige JSON-Eingaben. Die Ergebnisse
weisen die implementierten Verträge nach, keine Malware-Erkennungsrate.

Die vollständige Windows-Workspace-Suite besteht mit **1.430 bestandenen Tests,
0 Fehlern und 1 bereits zuvor ignorierten Generator**. Der Daemon behält seine
17 Workspace-Abhängigkeiten. Lokale Prüfprotokolle liegen unter
`target/restart-audit/netanalysis-*`.

Windows-Build und Workspace-Clippy für alle Targets mit `-D warnings` sowie
Format-/Diff-Prüfung bestehen. Die neue Komponente besteht auch Clippy für alle
Targets unter `x86_64-unknown-linux-gnu`; Linux-Tests wurden hier nicht ausgeführt.
Das Beispiel wurde mit dem gebauten Programm ausgewertet und liefert die vier
erwarteten Kriterien. Der lokale Bericht liegt unter
`target/restart-audit/netanalysis-example-report.json`.
