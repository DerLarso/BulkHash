# Projekt-Checkliste: BulkHash

Legende:
[X] = Feature fehlt
[O] = Feature ist in Arbeit
[#] = Feature ist gut und ohne Bugs implementiert
[/] = Feature wird erstmal nicht implementiert

Backend - Core & Hashing:
	[#] Datei-Hashing (Blake3 & SHA256): Speichereffizientes Hashen mit 64KB-Buffer ; Rust
	[#] Rekursiver Ordner-Scanner: Durchsucht Verzeichnisse inklusive Systempfad-Ausnahmen ; Rust
	[#] Symlink-Filter: Überspringt symbolische Links zur Vermeidung von Endlosschleifen ; Rust
	[#] Einzeldatei-Hashing: Gezieltes Hashen einer einzelnen Datei statt eines ganzen Ordners ; Rust
	[#] Weitere Hash-Algorithmen: Unterstützung für MD5, SHA512 und xxHash (extrem schnell) ; Rust
	[#] Multithreading-Scanner: Paralleles Hashen mehrerer Dateien über alle CPU-Kerne (Rayon) ; Rust
	[#] Scan-Abbruchfunktion: Sicheres Stoppen eines laufenden Scan-Vorgangs über AtomicBool ; Rust
	[#] Pause- & Fortsetzen-Funktion: Laufende Scans temporär pausieren und weiterführen ; Rust
	[#] Ignore-Listen Support: Überspringen von Ordnern/Dateien per Muster (z. B. node_modules, .git) ; Rust
	[#] Versteckte Dateien filtern: Option zum Ein- oder Ausschließen von Dotfiles/Systemdateien ; Rust

Backend - Dateiformat & IO (.hashed):
	[#] ZIP-Containerformat: Speichern und Laden von meta.json, tree.json und hash.sha256 ; Rust
	[#] Manipulationsschutz: Validierung der tree.json beim Laden über den gespeicherten SHA256-Hash ; Rust
	[#] Basis-Metadaten: Erfassung von Betriebssystem, Zeitstempel, Hash-Dauer und Dateianzahl ; Rust
	[#] Baumstruktur-Generierung: Aufbau des DirectoryNode (Anpassung auf relative Pfade fehlt noch) ; Rust
	[#] Eigenes Error-Handling: Zentrale HashedError-Enum (Ausformulierte Display-Texte fehlen noch) ; Rust
	[#] Erweiterte Datei-Metadaten: Speichern von Dateigröße und letztem Änderungsdatum pro Datei ; Rust
	[#] Versions-Migration: Abwärtskompatibilität für zukünftige Versionen des .hashed-Formats ; Rust
	[#] Snapshot-Verschlüsselung: Optionaler Passwortschutz (AES-GCM) für sensible Dateibäume ; Rust
	[#] Snapshot-Komprimierungsgrad: Einstellbare ZIP-Kompressionsstärke (Schnell vs. Kleine Datei) ; Rust
	[/] Die tree.json segmentieren für schnelleren zugriff und weniger ram Auslastung, wenn nicht der ganze Baum gebraucht wird ; Rust

Backend - Diff-Engine & Analyse:
	[#] Baum-Vergleichsalgorithmus: Rekursiver Abgleich von zwei DirectoryNode-Strukturen ; Rust
	[#] Datei-Status-Erkennung: Kategorisierung in Unverändert, Geändert, Neu, Gelöscht und Fehler ; Rust
	[/] Move- & Rename-Erkennung: Identifizieren verschobener oder umbenannter Dateien anhand gleicher Hashes ; Rust
	[#] Ordner-Status-Propagation: Markiert übergeordnete Ordner farbig, wenn sich tiefere Dateien geändert haben ; Rust
	[#] Diff-Statistiken: Berechnung der Gesamtzahl aller Änderungen sowie der Speicherplatz-Differenz ; Rust
	[X] Live-Ordner-Vergleich: Direktes Prüfen einer .hashed-Datei gegen einen echten Ordner auf der Festplatte ; Rust
	[X] Duplikat-Finder: Aufspüren identischer Dateien (gleicher Hash) innerhalb eines einzelnen Snapshots ; Rust
	[X] Bitrot- / Integritäts-Check: Prüfung auf beschädigte Dateien bei unverändertem Änderungsdatum ; Rust

Backend - Tauri, IPC & System-Integration:
	[O] Tauri-App-Setup: Grundgerüst der Desktop-App (temporäre CLI-Testfunktion muss noch ersetzt werden) ; Rust
	[X] Tauri-Commands (IPC): Schnittstellen-Funktionen für Scan, Datei-Laden und Diff-Vergleich ; Rust
	[X] Live-Fortschritts-Events: Senden von aktueller Datei, Prozentstand und MB/s an das Frontend ; Rust
	[X] Native Dateidialoge: Öffnen des System-Explorers zur Ordner- und Dateiauswahl ; Rust / TypeScript
	[X] OS-Benachrichtigungen: Desktop-Notification, wenn ein großer Scan im Hintergrund fertig ist ; Rust / TypeScript
	[X] Dateityp-Verknüpfung: Doppelklick auf eine .hashed-Datei im System startet direkt die App ; Rust
	[X] Kontextmenü-Integration: Rechtsklick im Windows-Explorer/Finder "Mit Hashed scannen" ; Rust
	[X] Headless-CLI-Modus: Steuerung des Programms über das Terminal für automatisierte Update-Skripte ; Rust
	[X] Lokale Einstellungsverwaltung: Speichern von Nutzer-Präferenzen und letzten Dateien als JSON ; Rust

Frontend - Grundgerüst, Layout & Design:
	[X] Svelte + TypeScript Setup: Basis-Architektur mit Komponenten-Struktur und State-Management ; Svelte / TypeScript
	[X] TypeScript-Datenmodelle: Interfaces passend zu allen Rust-Structs (MetaData, DirectoryNode, Diff) ; TypeScript
	[X] Theme-Umschalter: Wechsel zwischen Dark-Mode, Light-Mode und automatischem System-Theme ; Svelte / CSS
	[X] Mehrsprachigkeit (i18n): Sprachauswahl für Deutsch und Englisch in der gesamten Oberfläche ; TypeScript
	[X] App-Navigation: Übersichtliche Sidebar oder Tab-Leiste für Scanner, Explorer, Diff und Settings ; Svelte / HTML
	[X] Globale Statusleiste: Fußzeile mit aktuellem Programmstatus, aktivem Algorithmus und RAM-Verbrauch ; Svelte / TypeScript
	[X] Tastenkürzel (Shortcuts): Schnelle Bedienung über Hotkeys (z. B. Strg+O, Strg+F, Esc zum Abbrechen) ; TypeScript

Frontend - Scanner & Snapshot-Explorer:
	[X] Start-Dashboard: Schnellstart-Kacheln und Liste der zuletzt geöffneten .hashed-Snapshots ; Svelte / HTML
	[X] Drag & Drop Zone: Hineinziehen von Ordnern zum Scannen oder .hashed-Dateien zum Öffnen ; Svelte / TypeScript
	[X] Scan-Konfigurator: Auswahl von Zielordner, Hash-Algorithmus und Ignore-Optionen vor dem Start ; Svelte / TypeScript
	[X] Animierte Fortschrittsanzeige: Live-Ladebalken mit Dateizähler, Geschwindigkeit und Restzeit (ETA) ; Svelte / CSS
	[X] Metadaten-Karten: Visuelle Darstellung von OS, Scan-Dauer, Datum und Prüfsumme des Snapshots ; Svelte / HTML
	[X] Interaktiver Dateibaum: Auf- und zuklappbare Ordnerstruktur mit passenden Datei-Icons ; Svelte / TypeScript
	[X] Virtuelles Scrolling: Flüssiges Scrollen im Dateibaum auch bei über 100.000 Dateien ; Svelte / TypeScript

Frontend - Visueller Diff-Vergleich (Hauptfeature):
	[X] Snapshot-Auswahlleiste: Gegenüberstellung von "Vor dem Update" (Links) und "Nach dem Update" (Rechts) ; Svelte / HTML
	[X] Diff-Zusammenfassungs-Badges: Farbige Zähler für +Neu, ~Geändert, -Gelöscht, ->Verschoben und =Gleich ; Svelte / CSS
	[X] Farbcodierter Diff-Baum: Visuelle Markierung der Zeilen (Grün, Gelb, Rot, Blau, Grau) im Dateibaum ; Svelte / CSS
	[X] Ansichts-Umschalter: Wechsel zwischen kombinierter Baumansicht (Unified) und Split-Screen (Side-by-Side) ; Svelte / TypeScript
	[X] Schnellfilter-Schalter: Ein-/Ausblenden von unveränderten Dateien mit einem Klick ; Svelte / TypeScript
	[X] Status-Filter: Gezieltes Filtern nach nur neuen, nur gelöschten oder nur veränderten Dateien ; Svelte / TypeScript
	[X] Echtzeit-Suchleiste: Durchsuchen des Dateibaums nach Namen, Pfaden oder Dateiendungen (z. B. .dll) ; Svelte / TypeScript
	[X] Datei-Detail-Inspektor: Seitenleiste mit altem vs. neuem Hash, Größenunterschied und Zeitstempel ; Svelte / HTML
	[X] Speicherplatz-Visualisierung: Kleines Balken- oder Treemap-Diagramm für Größenänderungen pro Ordner ; Svelte / TypeScript
	[X] Explorer-Schnellzugriff: Button an jeder Datei, um ihren Speicherort direkt im OS-Dateimanager zu öffnen ; TypeScript / Rust

Export & Reporting:
	[X] Markdown-Changelog-Export: Speichert die gefundenen Update-Änderungen als formatierte .md-Datei ; Rust / TypeScript
	[X] HTML-Report-Generator: Exportiert den Diff-Vergleich als eigenständige, teilbare Webseite ; Rust / HTML
	[X] CSV- / JSON-Datenexport: Exportiert Tabellen und Rohdaten für Excel oder externe Skripte ; Rust
	[X] One-Click-Clipboard: Kopieren von Hashes, Dateinamen oder relativen Pfaden per Klick in die Zwischenablage ; TypeScript

App-Ökosystem, Support & Extras:
	[X] "Buy Me a Coffee"-Integration: Unterstützer-Button mit Link/QR-Code im Footer und Über-Menü ; Svelte / HTML
	[X] GitHub-Sponsors / Ko-fi Link: Weitere Optionen für Spenden und Projekt-Support ; Svelte / HTML
	[X] "Über Hashed"-Dialog: Modal mit App-Version, Lizenzinfos, Credits und Link zum Quellcode ; Svelte / HTML
	[X] In-App Bug-Reporter: Button, der ein vorausgefülltes GitHub-Issue inklusive Systeminfos öffnet ; TypeScript
	[X] Auto-Updater: Automatische Prüfung auf neue Programmversionen beim App-Start ; Rust / TypeScript
	[X] Einstellungs-Seite: Konfiguration von Standard-Algorithmus, Thread-Anzahl und Speicherorten ; Svelte / TypeScript
	[X] Onboarding-Tour: Kurzes interaktives Tutorial beim allerersten Start des Programms ; Svelte / TypeScript
	[X] Sound-Effekte (Optional): Dezenter Hinweiston, wenn ein langer Scan- oder Diff-Vorgang abgeschlossen ist ; TypeScript