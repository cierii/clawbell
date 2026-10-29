# clawbell

Lokalny rdzeń proxy MCP w Rust (edition 2024, Tokio). Transporty przekazują
komunikaty przez obowiązkowy adapter kontroli bezpieczeństwa. Projekt jest na
etapie biblioteki transportowej; binarka `clawbell` pozostaje pustym scaffoldingiem.

Dostępne API:

- `clawbell_proxy::stdio::run`: asynchroniczny menadżer procesu MCP. Uruchamia
  serwer przez `clawbell_sandbox::Runner`, obsługuje osobne zadania odczytu/zapisu,
  drenuje i odrzuca stderr z limitem, kończy i zbiera proces po zakończeniu sesji.
- `clawbell_proxy::stdio::relay`: pompa dwóch już połączonych transportów STDIO.
- `clawbell_proxy::http::relay`: klient STDIO → zdalny, bezstanowy endpoint
  Streamable HTTP. Każda wiadomość jest osobnym POST; odpowiedź może być JSON
  albo skończonym SSE z powiadomieniami i skorelowaną odpowiedzią.
- `clawbell_proxy::protocol`: walidacja JSON-RPC 2.0 i schematów MCP przez adapter
  oficjalnego SDK `rmcp`; fazy `New`, `Initializing`, `AwaitingInitialized`,
  `Ready`, `Closed`, osobne przestrzenie ID oraz terminy żądań w obu kierunkach.

Każdy kierunek podlega kontroli `Gate`, również powiadomienia, resources, prompts,
sampling i elicitation. Nie ma domyślnej implementacji przepuszczającej ruch.
`Gate` musi dostarczyć niezmienny snapshot polityki, przypięcie tożsamości i
schematów narzędzi, kontrolę argumentów i sekretów oraz trwały audyt przed
wykonaniem. `finish` zapisuje zakończenie i nieznane wyniki. Przerwane zamiary
muszą pozostać w audycie jako nieznane również po anulowaniu całej future.
Transport sam nie implementuje tych mechanizmów.

`Runner` jest granicą zaufanego mechanizmu izolacji. Implementacja musi sprawdzić
bubblewrap, seccomp i cgroups v2, ograniczyć środowisko, mounty, sieć i zasoby oraz
zapewnić sprzątanie całego drzewa także przy porzuceniu future. Brak konkretnego
runnera uniemożliwia produkcyjne uruchomienie lokalnego serwera. Implementacje
polityki, SQLite i sandboxa wymagają kolejnego etapu; testowe adaptery są wyłącznie
syntetycznymi fixtures. Nie stanowią gotowego firewalla.

## Transport i ograniczenia

STDIO używa pojedynczego JSON na linię, bez nagłówków Content-Length. Rozmiar
linii jest ograniczony podczas odczytu, przed alokacją całej wiadomości.
Czytniki i pisarze pracują niezależnie; kolejki są ograniczone i przeciążenie
zamyka sesję. Domyślnie: 1 MiB, 32 wiadomości na kolejkę, 32 oczekujące żądania
na kierunek i 30 s na I/O, kontrolę lub oczekiwanie bez postępu. Maksymalnie
65 536 unikalnych ID na kierunek; ID nie mogą być ponownie użyte. JSON odrzuca
zduplikowane klucze, nadmierne zagnieżdżenie, batch, null/fractional IDs i nieznane
metody. Obsługiwane wersje: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25.
Nieznane rozszerzenia wymagają świadomej rozbudowy adaptera.

HTTP wymaga HTTPS; wyjątek HTTP dotyczy wyłącznie konkretnego adresu loopback
wskazanego przez właściciela. DNS jest rozwiązywany raz i przypinany do
zweryfikowanych adresów, bez środowiskowego proxy, przekierowań i ponowień.
Prywatne cele wymagają wyjątku dla dokładnego IP i endpointu; link-local,
metadata i adresy IPv4 mapowane w IPv6 są odrzucane. Dane logowania w URL,
query i fragment są niedozwolone. Nie ma jeszcze adaptera poświadczeń upstreamu.

Adapter HTTP jest bezstanowy: nie obsługuje `Mcp-Session-Id`, GET, wznawiania SSE,
legacy HTTP+SSE ani interaktywnych żądań serwer → klient w SSE. Te przypadki są
odrzucane. Cała skończona odpowiedź HTTP jest buforowana z limitem przed
inspekcją; strumień nie może pozostać otwarty bez końca. Klient musi uwzględniać
te ograniczenia przy wyborze upstreamu. Nie deklarujemy zgodności z każdym
istniejącym serwerem ani uniwersalnej gwarancji opóźnienia.

Lokalne `notifications/cancelled` zamyka sesję i uruchamia teardown runnera;
zdalne jest przekazywane przez POST, bez obietnicy cofnięcia skutków. EOF,
niepoprawny protokół, odmowa lub timeout zamykają całą sesję. Wiadomości nadal
oczekujące w kolejkach mogą zostać odrzucone; niezakończone operacje mają wynik
nieznany. Transport nie wypisuje surowych błędów, payloadów ani stderr upstreamu.

## Weryfikacja

Wymagany jest przypięty toolchain z `rust-toolchain.toml`. Test procesu korzysta
z `/usr/bin/python3` i stałego syntetycznego serwera; testy HTTP wymagają bind na
loopbacku. Nie łączą się z publicznymi usługami i nie pobierają serwerów MCP.

```bash
cargo fetch --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast
cargo build --workspace --release --locked
cargo test -p clawbell-proxy --release --locked latency_under_three_ms -- --ignored --nocapture
```

Ostatnie polecenie to jawny eksperyment wydajnościowy: 200 rozgrzewających i 2000
mierzonych round-tripów `ping`, 2 wątki Tokio, porównanie bezpośredniego połączenia
z proxy przez pamięciowe strumienie z backpressure. Wypisuje percentyle i sprawdza
różnicę p99 poniżej 3 ms. Testowy gate nie wykonuje trwałego zapisu: wynik nie
obejmuje SQLite, sandboxa, procesu ani sieci i nie potwierdza warunku <3 ms dla
pełnej konfiguracji produkcyjnej. Pomiar nie stanowi górnej granicy pojedynczej
operacji na dowolnym hoście.

Specyfikacje: [transporty MCP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
[cykl życia](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle),
[oficjalny SDK rmcp](https://github.com/modelcontextprotocol/rust-sdk).
