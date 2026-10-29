# clawbell — konstytucja projektu

## Zakres i trwałość zasad

- Ten plik obowiązuje w całym repozytorium i opisuje docelowe kontrakty projektu.
- Zmieniaj go wyłącznie przy świadomej zmianie architektury lub zasad współpracy.
- Status zadań, backlog i wyniki pojedynczych sesji przechowuj poza tym plikiem.
- Zmiany granic zaufania dokumentuj w `docs/adr/` wraz z uzasadnieniem i migracją.
- Na etapie ustanawiania konstytucji jedynym tworzonym plikiem jest `AGENTS.md`.

## Wizja i cel produktu

clawbell to lokalne proxy, firewall, sandbox i audytor dla MCP oraz agent skills, oceniający operacje przed ich wykonaniem.
Przechwytuje ruch między agentem a narzędziami, stosuje jawne polityki i maskuje sekrety przed ujawnieniem odbiorcom.
Blokuje nieautoryzowane zapisy, destrukcyjne polecenia, dostęp poza dozwolonym katalogiem i eksfiltrację przez kontrolowane kanały.
Ogranicza skutki prompt injection, podmiany narzędzi i złośliwych skills przez minimalne uprawnienia oraz izolację wykonania.
Nie gwarantuje rozpoznania każdej manipulacji ani ochrony operacji omijających proxy i runner.

## Model zagrożeń i granice zaufania

- Zaufane są konfiguracja właściciela, silnik polityk i mechanizmy izolacji hosta.
- Niezaufane są argumenty, opisy narzędzi, wyniki MCP, pliki repozytoriów i treść skills.
- Instrukcja znaleziona w wyniku narzędzia lub `SKILL.md` nie nadaje uprawnień.
- Zakładamy nieuprzywilejowanego użytkownika i brak przejęcia jądra systemu.
- Nie obiecuj odporności audytu na administratora ani na przejęcie konta właściciela.
- Zdalny serwer MCP podlega kontroli ruchu; jego procesów nie izoluje lokalny sandbox.
- Skill uruchamiany poza kontrolowanym runnerem pozostaje poza granicą egzekwowania.
- Ochrona jest lokalna; telemetria i przesyłanie danych do chmury są domyślnie wyłączone.

## Wybrany stack i uzasadnienie

- Backend: Rust, edition 2024; bezpieczeństwo pamięci i pojedynczy natywny program.
- Runtime: Tokio; współbieżne transporty, kontrolowane kolejki i anulowanie operacji.
- MCP: `rmcp`, oficjalny Rust SDK; adapter izoluje zależność od wersji protokołu.
- Dane: `serde`, `serde_json`, `toml`; typowane komunikaty i czytelne polityki lokalne.
- Walidacja: `jsonschema`; zgodność argumentów z przypiętym schematem narzędzia.
- CLI: `clap`; jednoznaczne subkomendy, walidowane flagi i generowana pomoc.
- API panelu: `axum`; lokalny HTTP i SSE do prezentacji zredagowanych zdarzeń.
- HTTP wychodzący: `reqwest` z `rustls`; jeden kontrolowany adapter sieciowy.
- Audyt: SQLite przez `rusqlite`; transakcje lokalne bez osobnego serwera bazy.
- Diagnostyka: `tracing`; wyłącznie pola po redakcji, bez automatycznego dumpu żądań.
- Sekrety: `secrecy` i `zeroize`; ograniczenie przypadkowego logowania i czasu życia kopii.
- Sandbox: Linux, `bubblewrap`, seccomp i cgroups v2; izolacja procesów i limity zasobów.
- Panel: TypeScript w trybie strict, React i Vite; prosty interfejs lokalnego audytu.
- Testy: Rust test runner i `proptest`; Vitest oraz Playwright dla panelu.
- Rust i Node przypinaj w `rust-toolchain.toml` i `.node-version`; wersje nie należą tutaj.
- Commituj `Cargo.lock` i `ui/package-lock.json`; aktualizacje zależności są świadome.

## Architektura i odpowiedzialności

- Jeden workspace Cargo; binarka i pakiet CLI nazywają się `clawbell`.
- `crates/core/`: typy domenowe, deterministyczne polityki i redakcja; bez sieci i UI.
- `crates/proxy/`: sesje MCP, adaptery stdio/Streamable HTTP i egzekwowanie decyzji.
- `crates/sandbox/`: runner skills i serwerów MCP oraz kontrola zasobów procesów.
- `crates/audit/`: migracje SQLite, zapis zdarzeń i bezpieczny odczyt historii.
- `crates/clawbell/`: CLI, składanie zależności i lokalne API panelu.
- `ui/`: panel; nie zawiera silnika polityk ani uprawnień do wykonania narzędzi.
- `policies/`: wersjonowane przykłady; `tests/fixtures/`: wyłącznie syntetyczne dane.
- `docs/adr/`: decyzje trwałe; `docs/handoff.md`: aktualny punkt wznowienia pracy.
- Przepływ: odbiór → walidacja → ocena polityki → audyt zamiaru → wykonanie → redakcja → audyt wyniku.
- Przed wykonaniem stosuj również kontrolę sekretów na granicy żądania wychodzącego.
- SQLite obsługuje dedykowany writer; blokujące I/O nie zatrzymuje runtime Tokio.
- Panel jest opcjonalny; jego awaria nie omija zabezpieczeń ani nie zatrzymuje CLI.

## Niezmienniki polityk i protokołu

- Domyślna decyzja to `deny`; błąd, timeout lub nieznana reguła nie oznaczają zgody.
- Wynik oceny ma postać `allow`, `deny` albo `require_approval` i stały kod przyczyny.
- Odmowa ma pierwszeństwo; zatwierdzenie spełnia tylko jawne `require_approval`.
- Zgoda wiąże sesję, serwer, narzędzie, skrót argumentów, wersję polityki i termin ważności.
- Zgoda jest jednorazowa; zmiana argumentów lub polityki wymusza ponowną ocenę.
- Żądanie korzysta z jednego niezmiennego snapshotu polityki przez cały przebieg.
- Ładowanie polityki jest atomowe; błędna aktualizacja zachowuje ostatnią poprawną wersję.
- Brak poprawnej polityki przy starcie uniemożliwia wykonanie narzędzi.
- Waliduj JSON-RPC, schematy, rozmiary, głębokość, identyfikatory i kolejność inicjalizacji.
- Negocjuj wyłącznie obsługiwane wersje MCP; nie przepuszczaj nieznanych metod bez polityki.
- Zachowuj korelację odpowiedzi i izolację sesji; dane jednego klienta nie trafiają do drugiego.
- Kontroluj także resources, prompts, notifications i żądania serwer → klient.
- Sampling, elicitation i inne zdolności wymagają osobnego, jawnego uprawnienia.
- Deklaracje bezpieczeństwa i adnotacje narzędzia są wskazówkami, nigdy autoryzacją.
- Przypinaj tożsamość serwera oraz schemat narzędzia; ich zmiana unieważnia wcześniejsze zgody.
- `stdout` transportu stdio zawiera tylko MCP; diagnostyka trafia na zredagowany `stderr`.
- Każda kolejka, wiadomość i operacja ma limit; przeciążenie kończy się kontrolowaną odmową.
- Anulowanie kończy pracę runnera i jego potomków; nie twierdzi, że cofa skutki zdalnej operacji.
- Nie ponawiaj automatycznie operacji ze skutkami ubocznymi po utracie odpowiedzi.

## Niezmienniki sandboxa i sieci

- Wykonuj procesy bez roota, z pustym środowiskiem rozszerzanym wyłącznie przez allowlistę.
- Buduj argumenty procesu jako tablicę; nie sklejaj niezaufanych danych do `sh -c`.
- Uruchomienie powłoki przez skill wymaga izolacji i jawnego uprawnienia polityki.
- System plików jest domyślnie tylko do odczytu; zapisy obejmują konkretne katalogi robocze.
- Nie montuj całego katalogu domowego, gniazda Dockera, agenta SSH ani katalogów poświadczeń.
- Sprawdzaj ścieżki na rzeczywistych uchwytach; uwzględniaj symlinki i wyścigi TOCTOU.
- Sieć sandboxa jest domyślnie odłączona; wyjątki przechodzą przez egzekwujący politykę broker.
- Allowlista dotyczy celu, portu i protokołu; samo ustawienie zmiennej proxy nie izoluje sieci.
- Weryfikuj DNS i adres użyty do połączenia, każdy redirect oraz cele prywatne i metadata usług chmurowych.
- Lokalny upstream MCP wymaga osobnego jawnego wyjątku; nie otwieraj całego loopbacku.
- TLS jest weryfikowany; nie wyłączaj walidacji certyfikatów dla wygody integracji.
- Nakładaj limity CPU, RAM, liczby procesów, czasu i wyjścia na całe drzewo procesów.
- Przed startem sprawdzaj dostępność izolacji; brak wymaganej funkcji oznacza odmowę.
- Linux jest pierwszą platformą egzekwowania; inne systemy nie dostają cichego trybu bez sandboxa.
- Nazwa lub hash skilla identyfikuje zawartość, lecz sam w sobie nie dowodzi jej bezpieczeństwa.

## Sekrety, audyt i lokalny panel

- Redaguj żądania, odpowiedzi, błędy, metadane, logi i eksporty przed przekroczeniem granicy zaufania.
- Rozpoznawaj jawnie zarejestrowane sekrety i wzorce; heurystyki nie gwarantują pełnej wykrywalności.
- Zastępuj sekret stabilnym w obrębie sesji, nieodwracalnym identyfikatorem, bez ujawniania wartości.
- Jeśli redakcja psuje schemat lub znaczenie argumentów, odmawiaj zamiast wykonywać zmienioną operację.
- Poświadczenia dla zatwierdzonego upstreamu wstrzykuj tylko w adapterze docelowym.
- Nie przekazuj poświadczeń do modelu, panelu ani innych serwerów; nie odtwarzaj sekretów z tekstu narzędzia.
- Buforuj pełną jednostkę podlegającą inspekcji przed wysłaniem; uwzględniaj sekrety dzielone na fragmenty.
- Przekroczenie limitu bufora lub nieobsługiwany format oznacza odmowę albo jawne odrzucenie pola.
- Audyt zawiera identyfikator korelacji, czas UTC, wersję polityki, decyzję i wynik bez surowych danych.
- Zapisz trwale zamiar przed wykonaniem; brak możliwości zapisu blokuje nowe operacje.
- Po awarii rozróżniaj wynik nieznany od sukcesu; nie odtwarzaj automatycznie niezakończonych operacji.
- Ogranicz rozmiar i retencję audytu; pliki danych mają dostęp tylko dla właściciela.
- Audyt jest dopisywany; każda autoryzowana retencja lub migracja pozostawia ślad.
- API i panel nasłuchują na loopbacku; wymagają tokenu, walidacji Host/Origin i ochrony przed CSRF.
- Nie używaj CORS `*`; tokenów nie umieszczaj w URL, logach ani localStorage.
- Wyniki narzędzi renderuj jako niezaufany tekst; wyłącz surowy HTML i automatyczne otwieranie linków.
- Zatwierdzenie pokazuje zakres skutków i zredagowane argumenty; wykonanie ponownie sprawdza jego ważność.

## Rób i unikaj

- Rób małe zmiany z jednym celem; zachowuj istniejące zmiany użytkownika.
- Oddzielaj czystą ocenę polityk od efektów ubocznych; każdy efekt przechodzi przez adapter.
- Używaj typowanych błędów i kodów przyczyn; komunikaty mają pomagać bez ujawniania danych.
- Preferuj minimalny zestaw zależności i features; uzasadniaj nowe zależności bezpieczeństwem lub funkcją.
- `unsafe` dopuszczaj tylko w małym adapterze systemowym z opisanym kontraktem i przeglądem.
- Nie używaj `unwrap`, `expect` ani panik dla niezaufanych danych w kodzie produkcyjnym.
- Nie implementuj własnej kryptografii; nie traktuj regexów ani LLM jako jedynego zabezpieczenia.
- Nie wyłączaj testów, walidacji, izolacji ani audytu w celu uzyskania zielonego CI.
- Nie zapisuj prawdziwych sekretów w fixture, snapshotach, issue ani dokumentacji.
- Nie dodawaj ukrytej telemetrii, automatycznych aktualizacji ani pobierania wykonywalnych skills.

## Komendy operacyjne

Komendy wykonuj z katalogu głównego repozytorium w Bash; poniższe kontrole działają już teraz:
```bash
git status --short --branch
git diff --check
wc -l AGENTS.md
```
Poniższe komendy są kontraktem przyszłego scaffoldingu, nie deklaracją istniejącej implementacji.
Wymagają manifestów, lockfile, przypiętych Rust/Node, npm oraz systemowego `bwrap`.
Scaffolding ma dostarczyć pakiet `clawbell`, przykład polityki, skrypty npm i inicjalizację chronionego pliku tokenu.
```bash
rustup show active-toolchain
bwrap --version
cargo fetch --locked
npm --prefix ui ci --ignore-scripts
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast
cargo build --workspace --release --locked
npm --prefix ui run typecheck -- --pretty false
npm --prefix ui run lint -- --max-warnings=0
npm --prefix ui run test -- --run
npm --prefix ui run build
npm --prefix ui run test:e2e -- --reporter=line
cargo run --locked -p clawbell -- --help
cargo run --locked -p clawbell -- policy check --file policies/default.toml
cargo run --locked -p clawbell -- serve --policy policies/default.toml --listen 127.0.0.1:7391 --token-file .local/clawbell/admin.token
```
Skrypty npm mapują się na `tsc --noEmit`, `eslint .`, `vitest`, `vite build` i `playwright test`; E2E wymaga przeglądarek testowych.
`serve` wymaga pliku tokenu z prawami `0600`; `.local/` jest poza Gitem, a wartość tokenu nigdy nie trafia do argumentu CLI.
Nie obchodź błędów `--locked`; brak manifestu lub narzędzia raportuj jako niewykonaną kontrolę.
Instalacyjne skrypty zależności dopuszczaj pojedynczo po przeglądzie; nie wyłączaj globalnie `--ignore-scripts`.

## Definicja ukończenia zadania

- [ ] Zakres i kryteria użytkownika są spełnione; nie dodano niezamówionych funkcji.
- [ ] Zmiana zachowuje powyższe niezmienniki, a odstępstwo ma zaakceptowaną decyzję architektoniczną.
- [ ] Dla zmiany zachowania istnieją adekwatne testy, w tym odmowa i brak niedozwolonych skutków ubocznych.
- [ ] Zmiany granic bezpieczeństwa sprawdzono na próbach obejścia, awarii i wycieku syntetycznego sekretu.
- [ ] Odpowiednie formatowanie, lint, typowanie, testy i build przechodzą bez nowych ostrzeżeń.
- [ ] Zmiany UI zweryfikowano w przeglądarce; klawiatura i prezentacja decyzji pozostają czytelne.
- [ ] Dokumentacja i kontrakty komend odpowiadają zmianie; przykłady nie zawierają sekretów.
- [ ] Diff jest sprawdzony i nie narusza cudzych zmian; brak przypadkowych plików i danych.
- [ ] Raport podaje rezultat, wykonane kontrole i ograniczenia; niewykonane testy nie są „zaliczone”.
- [ ] Zadanie wyłącznie dokumentacyjne wymaga kontroli treści, linków, zakresu i liczby linii, bez testów aplikacji.

## Protokół wznawiania pracy

1. Przeczytaj `AGENTS.md`, `README.md`, istniejący `docs/handoff.md` i ADR dotyczące zadania.
2. Uruchom `git status --short --branch`, `git diff --stat` i `git log -5 --oneline`.
3. Ustal obecny cel, kryteria odbioru, lokalne zmiany i ostatnią potwierdzoną kontrolę.
4. Sprawdź manifesty i dostępne narzędzia; oddziel plan architektury od faktycznie wdrożonych funkcji.
5. Kontynuuj najmniejszy krok prowadzący do celu; nie resetuj repozytorium ani nie odtwarzaj pracy w ciemno.
6. Przy przerwaniu zapisz w `docs/handoff.md`: cel, wykonane zmiany, pliki, kontrole, blokady i następny krok.
7. Handoff nie zawiera sekretów ani zgód do ponownego użycia; respektuj zakres zapisu zlecony przez użytkownika.

## Źródła kontraktów technicznych

- MCP i SDK: [rmcp](https://github.com/modelcontextprotocol/rust-sdk) oraz [transporty MCP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).
- Izolacja: [bubblewrap](https://github.com/containers/bubblewrap); bezpieczeństwo zależy od nadanej konfiguracji sandboxa.
- Testy i flagi: [Cargo test](https://doc.rust-lang.org/cargo/commands/cargo-test.html).
