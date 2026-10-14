# PyChef Release Hardening Baseline (Phase 0)

- **Referenz-Commit:** `07d4a6f592264f6680b1baa6d66104bd8340502b`
- **Datum:** 2026-10-14
- **Paketversion:** `0.1.1` (pyproject.toml)
- **Lokale Python-Version:** Python 3.13.5 (macOS aarch64)
- **Baseline Testanzahl:** 1.089 Tests (1089 passed in 49.69s)
- **Baseline Code-Coverage:** 85.04% (Minimum required: 75%)
- **Statische Prüfungen:**
  - `ruff check .`: PASS (0 errors)
  - `ruff format --check .`: PASS (678 files formatted)
  - `ty check`: PASS (All checks passed)

## Bereits vorhandene Schutzmaßnahmen

1. **ExecutionPolicy & NetworkPolicy:**
   - Sichere Standardprofile (`ExecutionPolicy.safe()`, `untrusted()`, `permissive()`, `unrestricted()`).
   - Host- und IP-Filterung (`allowed_hosts`, `denied_hosts`, `allowed_subnets`, `denied_subnets`).
   - Private IP-Blockierung in `safe()` und `public_only()`.
   - DNS-Pinning via `_SafeHTTPConnection` und `_SafeHTTPSConnection`.
2. **Prozessisolation:**
   - `IsolatedWorker` via `multiprocessing` (Spawn-Modus).
   - Optionales RLIMIT_AS unter Linux.
3. **Lazy Loading & Registry:**
   - Manifest mit 502 Operationen.
   - Dynamisches Importieren bei Zugriff.
4. **Pipeline & Streaming:**
   - Generator-basiertes `iter_transform()`.
   - Grundlegendes Tracing mit Limits.

## Identifizierte offene Schwachstellen und Mängel (vor den Phasen)

1. **HTTP-Redirects & Credential Leaks (P0 - Phase 1):**
   - Standardbibliothek `urllib.request` übernimmt sensible Header (`Authorization`, `Cookie`, `Proxy-Authorization`) bei Weiterleitungen auch an fremde Origins.
   - Kein automatisches Stripping sensibler Header bei Cross-Origin-Redirects.
2. **NetworkPolicy & DNS-Entscheidungen (P0 - Phase 2):**
   - `allowed_subnets` wird in `_resolve_with_policy()` vor der DNS-Auflösung ausgewertet. Wenn eine Policy `mode="disabled"` mit `allowed_subnets` hat, wird ein Hostname vor der Auflösung blockiert, da die Ziel-IP noch nicht bekannt ist.
   - Fehlendes 3-Zustands-Entscheidungsmodell (`ALLOW`, `DENY`, `NEEDS_RESOLUTION`).
   - Regelpriorität Host-Allow vs. IP-Deny muss zwingend sicherstellen, dass IP-Deny gewinnt.
3. **Unbegrenzte Redirects & Timeouts (P0 - Phase 3):**
   - `max_redirects=None` führt zu TypeError in der Standardbibliothek, da `HTTPRedirectHandler` numerische Vergleiche durchführt.
   - Fehlende Entkopplung von PyChef-spezifischen Limits und Standardbibliotheks-Verhalten.
4. **ExecutionPolicy-Konfigurationssemantik (P1 - Phase 4):**
   - Saubere Unterscheidung zwischen `None` (deaktiviert), `0` und positiven Werten.
   - Vermeidung von Truthiness-Fallbacks (`x or DEFAULT`).
   - Validierung von Typen (z. B. `bool` nicht als `int` akzeptieren).
5. **Fehlerbehandlung & Datenvertraulichkeit (P1 - Phase 5):**
   - Öffentliche Fehlermeldungen dürfen keine sensiblen Eingaben, Header oder Schlüssel enthalten.
   - Strukturierte Error-Codes und sichere Fehlertransport-Mechanismen über Prozessgrenzen hinweg.
6. **Pipeline-Tracing & Ressourcenmessung (P1 - Phase 6):**
   - Tracing verwendet `len(value)` für beliebige Objekte (z. B. `{ "k": b"A" * 100_000_000 }` hat len=1).
   - Braucht konservative Bytegrößenbestimmung und konsistentes Budgeting.
7. **IsolatedWorker & Prozessmanagement (P1 - Phase 7):**
   - Timeout muss den gesamten Prozesslebenszyklus inklusive Startup erfassen.
   - Fehlertransport und Klassifikation (EOF darf nicht fälschlich als OOM gemeldet werden).
   - Thread-Sicherheit (Modell A: kontrolliertes Ablehnen paralleler Aufrufe auf derselben Worker-Instanz).
   - Cleanup nach Abbruch.
8. **Ressourcenlimits & Flow-Control (P1 - Phase 8):**
   - Delimiter-Budgeting und Absicherung bei Fork / Subsection / Jump.
9. **Registry, Lazy Loading & Metadaten (P2 - Phase 9):**
   - Registry-Isolation (Manifest `{}` darf keine Built-in-Operationen enthalten).
10. **CyberChef-Kompatibilität & Plattformtests (P2 - Phasen 10-11):**
   - Systematisches Differential Testing.
