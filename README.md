# CRYSTALS Kyber & Dilithium for Delphi / Pascal

Dieses Projekt ist eine möglichst direkte Übersetzung der offiziellen Referenzimplementierungen von **CRYSTALS-Kyber** und **CRYSTALS-Dilithium** aus den ursprünglichen C-Implementierungen der PQ-CRYSTALS-Projekte nach **Delphi / Object Pascal**.

Der Fokus liegt ausdrücklich nicht auf einer eigenständigen Neuinterpretation der Algorithmen, sondern auf einer nachvollziehbaren, strukturell nahen Portierung des Originalcodes.

## Herkunft der Implementierung

Dieses Projekt basiert direkt auf den offiziellen PQ-CRYSTALS-Repositories:

- [pq-crystals/kyber](https://github.com/pq-crystals/kyber)
- [pq-crystals/dilithium](https://github.com/pq-crystals/dilithium)

Die kryptographische Logik, Parameter, Funktionsstruktur und interne Organisation orientieren sich so weit wie möglich an den Originalimplementierungen.

Änderungen wurden nur dort vorgenommen, wo sie für die Umsetzung in **Delphi / Object Pascal** notwendig waren, zum Beispiel bei:

- Typdefinitionen
- Array- und Speicherzugriffen
- Pointer- und Buffer-Handling
- sprachspezifischen Konstanten und Deklarationen
- Anpassungen an Delphi-Compiler und Projektstruktur

## Ziel des Projekts

Ziel dieses Projekts ist es, die Referenzimplementierungen von **CRYSTALS-Kyber** und **CRYSTALS-Dilithium** für Delphi-Projekte verfügbar zu machen.

Durch die direkte Übersetzung soll der Code möglichst einfach mit den offiziellen C-Quellen vergleichbar bleiben. Das Projekt eignet sich daher insbesondere für:

- Tests
- Forschung
- Interoperabilitätsprüfungen
- Lern- und Analysezwecke
- Integrationsexperimente in Delphi-Anwendungen

## Enthaltene Algorithmen

## CRYSTALS-Kyber

**Kyber** ist ein post-quanten-sicheres Key-Encapsulation-Mechanism-Verfahren.

Dieses Projekt enthält die Kyber-Implementierung als Delphi-/Pascal-Port der offiziellen Referenzimplementierung.

Enthaltene Parameter-Sets:

- `Kyber512`
- `Kyber768`
- `Kyber1024`

Typische Operationen:

- Schlüsselpaar erzeugen
- Shared Secret kapseln
- Shared Secret entkapseln

## CRYSTALS-Dilithium

**Dilithium** ist ein post-quanten-sicheres digitales Signaturverfahren.

Dieses Projekt enthält die Dilithium-Implementierung als Delphi-/Pascal-Port der offiziellen Referenzimplementierung.

Enthaltene Parameter-Sets:

- `Dilithium2`
- `Dilithium3`
- `Dilithium5`

Typische Operationen:

- Schlüsselpaar erzeugen
- Nachricht signieren
- Signatur prüfen
- signierte Nachrichten erzeugen und verifizieren

## Projektstruktur

```text
.
├── kyber.pas              # Delphi/Pascal-Port der Kyber-Referenzimplementierung
├── dilithium.pas          # Delphi/Pascal-Port der Dilithium-Referenzimplementierung
├── fips202.pas            # SHA3 / SHAKE / Keccak-Funktionen
├── kyber_test.dpr         # Testprojekt für Kyber
└── dilithium_test.dpr     # Testprojekt für Dilithium
```

## Verwendung

Die Units können direkt in Delphi-Projekte eingebunden werden:

```pascal
uses
  kyber,
  dilithium,
  fips202;
```

Die konkreten Aufrufe richten sich nach den öffentlichen Funktionen der jeweiligen Units.

Beispiele befinden sich in den Testprojekten:

- `kyber_test.dpr`
- `dilithium_test.dpr`

## Status

Dieses Projekt ist ein Delphi-/Pascal-Port der offiziellen Referenzimplementierungen.

Es ist vor allem gedacht für:

- Vergleich mit den Originalimplementierungen
- Tests und Experimente
- Portabilitätsprüfungen
- Integration in bestehende Delphi-Codebasen

Vor einem produktiven Einsatz in sicherheitskritischen Umgebungen sollten zusätzliche Prüfungen durchgeführt werden.

## Sicherheitshinweise

Dieses Projekt sollte vor produktivem Einsatz sorgfältig geprüft werden.

Insbesondere empfohlen sind:

- Vergleich mit offiziellen Testvektoren
- kryptographisches Code Review
- Prüfung der Zufallszahlenerzeugung
- Side-Channel-Analyse
- Prüfung auf Compiler- und Plattformabhängigkeiten
- Interoperabilitätstests mit den offiziellen Referenzimplementierungen

Die direkte Übersetzung der Referenzimplementierungen bedeutet nicht automatisch, dass der Port für alle produktiven Einsatzszenarien sicher oder optimiert ist.

## Lizenz

Die Originalimplementierungen stammen aus den offiziellen PQ-CRYSTALS-Projekten:

- <https://github.com/pq-crystals/kyber>
- <https://github.com/pq-crystals/dilithium>

Bitte beachten Sie die Lizenzbedingungen der jeweiligen Originalprojekte.
