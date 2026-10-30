# Punkt wznowienia — 2026-10-30

## Cel i wynik

Zlecenie: In-Flight DLP Vault, dwukierunkowe znaczniki, test .env, kontrola
sekretów repozytorium, commit i push. Dostarczono komponenty biblioteczne
zintegrowane z istniejącą granicą Gate. CLI nadal jest scaffoldingiem; brak
produkcyjnego Gate z SQLite i Linux Runnera z poprzedniego etapu.

## Zmiany

- core/dlp.rs: ograniczony skaner fragmentów UTF-8, wzorce PEM/API/SSH/URI baz/
  credential assignments, jawna rejestracja, stabilne losowe znaczniki sesji,
  skarbiec XChaCha20-Poly1305 z kluczem SecretBox i zerowanymi buforami.
- proxy/dlp.rs: redakcja przed wewnętrznym audytem, odmowa surowych sekretów,
  odtwarzanie tylko w argumentach jawnie dozwolonego lokalnego narzędzia.
- Gate::validate_local_arguments: osobna walidacja rzeczywistych argumentów;
  domyślnie deny. HTTP odrzuca LocalVaultGate. finish usuwa vault.
- Testy .env przez rzeczywisty relay z fragmentacją wire, dwukierunkowe
  odtwarzanie oraz odmowy obcych tokenów, narzędzi i zakończonych sesji.
- ADR 0002 i celowana aktualizacja konstytucji dokumentują zamówiony wyjątek
  od zakazu odtwarzania sekretów z tekstu narzędzia. AGENTS.md nadal 199 linii.
- Nowe zależności: RustCrypto AEAD zamiast własnej kryptografii, systemowe
  getrandom, regex do heurystyk, secrecy/zeroize do ograniczania kopii sekretów.
- .gitignore rozszerzony o materiały kluczy prywatnych; fixtures syntetyczne.

## Kontrole

fmt, clippy --workspace --all-targets --locked z -D warnings, pełne testy
workspace i build release przeszły. Testy: 16 zwykłych testów oraz 1 rustdoc;
dwa eksperymenty są domyślnie ignored. Nowy eksperyment uruchomiono osobno.
Release DLP: 200 rozgrzewających i 2000 mierzonych jednostek po 2274 bajty,
64 zarejestrowane sekrety, fragmentacja co 97 bajtów, redakcja i odtwarzanie:
p99 259.572 µs, max 709.835 µs. Wynik poniżej 5 ms dotyczy wyłącznie tego
obciążenia i hosta; nie jest gwarancją pełnego proxy z trwałym audytem.

Gitleaks 8.30.1 (archiwum ze zweryfikowaną sumą SHA256): historia wszystkich
lokalnych refs (3 wcześniejsze commity) i kopia plików przeznaczonych do commitu
bez wykrytych wycieków. Początkowe wskazanie dotyczyło syntetycznego PEM w teście;
fixture składa teraz nagłówek z fragmentów bez wyłączania reguł skanera.
Skanery nie dowodzą nieobecności każdego sekretu i nie obejmują cudzych forków.

Toolchain 1.99.1 zainstalowany w /tmp/clawbell-rustup i /tmp/clawbell-cargo;
komendy wymagają odpowiednich RUSTUP_HOME/CARGO_HOME. Testy TCP wymagają
uprawnień poza sandboxem środowiska. UI/serve/policy check nie uruchamiano,
ponieważ nie mają implementacji i nie należą do tej zmiany.

## Ograniczenia i następny krok

DLP obejmuje obsługiwany tekst UTF-8, nie dowolne kodowanie czy załączniki
binarne. Vault nie blokuje swapu i nie chroni przed przejęciem procesu;
tymczasowe serde/transport plaintext copies nie mają gwarancji zerowania.
Composition root musi przypisać nowy vault każdej sesji jednego upstreamu,
zapewnić trwały audyt, przypięte schematy i izolowany Runner. Nie wprowadzać
permissive fallbacku. Pełna gwarancja wydajności wymaga pomiaru tej kompozycji.
