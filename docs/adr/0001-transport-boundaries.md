# 0001 — Obowiązkowe adaptery bezpieczeństwa rdzenia transportowego

Status: realizacja granic zapisanych w AGENTS.md; bez odstępstw od konstytucji.

## Kontekst i decyzja

Workspace nie zawiera jeszcze silnika polityk, SQLite ani Linuxowego sandboxa.
Transport musi być testowalny niezależnie, ale nie może wprowadzić domyślnego
trybu pozwalającego wykonywać operacje z pominięciem tych mechanizmów.

`clawbell-proxy` udostępnia generyczne funkcje transportowe wymagające `Gate`.
To zaufany adapter, który łączy politykę, kontrolę schematów i sekretów oraz trwały
audyt. Bez jego implementacji nie da się uruchomić przepływu. Inspekcja obejmuje
obie strony, również inicjalizację i powiadomienia. Błędy, przekroczenia limitów
i nieważne przejścia protokołu kończą sesję. Nie ma automatycznych ponowień.

Menadżer STDIO wymaga `clawbell-sandbox::Runner`; sam nie konstruuje polecenia
procesu z niezaufanych argumentów. Runner odpowiada za izolację hosta i całego
drzewa, także przy porzuceniu future. Menadżer odpowiada za rury, ograniczony
odczyt stderr, zakończenie i zebranie bezpośredniego procesu. Interfejs Rust nie
udowadnia poprawności izolacji: konkretna implementacja runnera podlega osobnemu
przeglądowi bezpieczeństwa.

Upstream HTTP jest bezstanowy. DNS i adresy połączeń są przypinane przy tworzeniu
celu przez właściciela. Każda odpowiedź przechodzi kontrolę przed wysłaniem do
klienta. W tej wersji nie obsługujemy sesji HTTP, GET, odtwarzania SSE,
poświadczeń upstreamu ani interaktywnych reverse requests w SSE. Nieznana
funkcja jest odrzucana, nie przekazywana transparentnie.

## Konsekwencje i integracja

Biblioteka jest rdzeniem do złożenia z adapterami produkcyjnymi, a nie gotowym
firewallem. Nie dodajemy nieizolowanego launchera ani produkcyjnego `AllowAll`.
Testy używają jawnych syntetycznych implementacji wyłącznie w pliku testowym.
Nie zmienia się istniejąca konfiguracja użytkownika i nie jest wymagana migracja.

Następna integracja musi dostarczyć gate oparty o niezmienny snapshot polityki,
SQLite writer i kontrolę schematów/sekretów oraz Linux runner egzekwujący
bubblewrap, seccomp i cgroups v2. Dopiero wtedy composition root CLI może
udostępnić uruchamianie rzeczywistych serwerów. Pomiar pełnej ścieżki, w tym
trwałego zamiaru przed wykonaniem, jest wymagany przed deklaracją <3 ms.
