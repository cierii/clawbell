# Punkt wznowienia — 2026-10-29

## Cel i stan

Zlecenie: rdzeń MCP proxy, menadżer STDIO/Tokio, walidacja JSON-RPC i faz MCP,
bezstanowy upstream HTTP/SSE oraz narzut poniżej 3 ms.

Dostarczono bibliotekę transportową. Nie dostarczono samodzielnego proxy CLI
z produkcyjnymi adapterami polityki, audytu i izolacji. Pełne kryterium
opakowania dowolnego rzeczywistego serwera z narzutem <3 ms pozostaje
niepotwierdzone. Nie deklarować zakończenia integracji produkcyjnej.

## Zmiany

- `crates/proxy/src/`: limity, statyczne błędy, obowiązkowy Gate, ścisły JSON,
  adapter rmcp, korelacja obu kierunków, lifecycle, asynchroniczne STDIO,
  bounded stderr, cleanup dziecka oraz stateless HTTP JSON/SSE z DNS pinning.
- `crates/sandbox/src/lib.rs`: wymagany kontrakt Runner; brak nieizolowanego fallbacku.
- `crates/proxy/tests/transports.rs`: wyłącznie syntetyczne fixtures, testy
  odmów, protokołu, backpressure, procesu, SSRF/HTTP i eksperyment wydajności.
- Manifesty i `Cargo.lock`: minimalne features Tokio/rmcp/reqwest oraz serde,
  serde_json, futures-util, thiserror; uzasadnienie to transport i walidacja.
- README i ADR 0001: publiczne API, zakres odpowiedzialności i ograniczenia.
- `AGENTS.md` pozostał bez zmian (199 linii); początkowy working tree był czysty.

## Potwierdzone kontrole

- `cargo fetch --locked`, fmt, clippy wszystkich targetów z `-D warnings`.
- Workspace tests: 12 zwykłych testów oraz kompilowany przykład rustdoc przechodzą;
  benchmark jest domyślnie ignored i został uruchomiony oddzielnie w release.
- Build release workspace i rustdoc z `RUSTDOCFLAGS='-D warnings'` przechodzą.
- `git diff --check` przechodzi; przejrzano nowe pliki i brak surowych logów w kodzie.
- Ostatni pomiar release: 2000 rozgrzanych ping RTT, 2 wątki Tokio, strumienie
  pamięciowe. Direct p99 27.643 µs, proxy p99 67.959 µs, różnica 40.316 µs;
  proxy max 204.027 µs. Nie obejmuje procesu, sieci ani trwałego audytu.
- Test procesu: 128 KiB stderr nie zakleszcza STDIO; anulowanie wywołuje teardown,
  bezpośredni proces zostaje zebrany. Test nie dowodzi izolacji potomków.
- Testy HTTP: JSON/SSE, jawny wyjątek loopback, brak wyjścia przy redirect,
  session ID, błędnej korelacji, nieobsługiwanym MIME i częściowym SSE.

Środowisko początkowo nie miało cargo/rustup. Oficjalny toolchain 1.99.1
zainstalowano wyłącznie w `/tmp/clawbell-rustup` i `/tmp/clawbell-cargo`, bez
modyfikacji profilu użytkownika. Polecenia wykonywano z `RUSTUP_HOME` i
`CARGO_HOME` ustawionymi na te ścieżki, binarką `/tmp/clawbell-cargo/bin/cargo`.
Testy HTTP wymagają uruchomienia z uprawnieniem bind na lokalnym TCP; pierwotny
sandbox środowiska blokował bind. Nie pomijano testów HTTP z tego powodu.
UI, npm, policy check i serve nie były uruchamiane: brak implementacji, poza
zakresem biblioteki. Nie traktować pustego main jako działającego CLI.

## Następny krok i ograniczenia

Zaimplementować Gate z rzeczywistą polityką, walidacją przypiętych tool schemas,
kontrolą sekretów i SQLite writerem oraz Linux Runner egzekwujący bwrap/seccomp/
cgroups v2. Następnie złożyć CLI i przetestować z rzeczywistymi upstreamami,
łącznie z próbami obejścia izolacji i pomiarem trwałego audytu w pełnej ścieżce.

HTTP obecnie odrzuca session IDs, GET/replay, interaktywne reverse requests i
nieskończone SSE. Nie ma adaptera auth. Wersja MCP 2026-07-28 z cyklem życia
bez initialize nie jest obsługiwana. Błąd/EOF zamyka całą sesję; wiadomości
pozostające w kolejce mogą zostać odrzucone, a wynik operacji pozostaje nieznany.
EOF, odmowa i timeout nie uruchamiają ponowień.
