# 0002 — Session-scoped In-Flight DLP Vault

Decyzja realizuje jawnie zlecone dwukierunkowe znaczniki. Stanowi wąski wyjątek
od zakazu odtwarzania sekretów z tekstu narzędzia: właściciel musi wskazać lokalny
upstream i listę narzędzi, a Gate musi oddzielnie zatwierdzić odtworzone argumenty.
Nie przywracamy sekretów do dowolnego odbiorcy wskazanego przez model.

Vault przechowuje wpisy zaszyfrowane XChaCha20-Poly1305, klucz sesji w SecretBox,
a nonce i znaczniki pochodzą z systemowego CSPRNG (192 bity). Nie ma persystencji,
Debug ani Clone. Wpisy są ograniczone do 128 oraz limitu sumy bajtów. Klucz i
bufory skanera/pomocniczego odszyfrowania są zerowane przy zwolnieniu. Nie jest
to ochrona przed odczytem pamięci procesu, swapem ani administratorem. Transport
i serde tworzą tymczasowe kopie plaintextu; nie deklarujemy zerowania wszystkich
alokacji ani blokowania stron RAM.

Scanner przyjmuje fragmenty bajtowe, lecz wypuszcza wynik dopiero po zakończeniu
całej ograniczonej jednostki. Transporty już buforują kompletne komunikaty MCP.
Inspekcja dotyczy tekstu UTF-8, PEM, znanych formatów kluczy API/SSH, URI baz i
przypisań credential w .env oraz pól JSON. Nie obejmuje dowolnego szyfrowania,
base64, archiwów, binarnych załączników ani wszystkich dostawców sekretów.
Jawna rejestracja wartości uzupełnia heurystyki. Niekompletny PEM, obcy znacznik,
limit i błąd kryptografii odmawiają przekazania jednostki.

LocalVaultGate otacza obowiązkowy Gate. Serwer → klient: redakcja przed audytem
wewnętrznego Gate. Klient → serwer: kontrola surowych sekretów, autoryzacja i audyt
znaczników, przywrócenie tylko w arguments tools/call, następnie osobna kontrola
validate_local_arguments względem przypiętego schematu i polityki. Domyślna
implementacja tej kontroli odmawia. HTTP odrzuca ten lokalny adapter. finish
usuwa vault, zamykając możliwość ponownego użycia sesji.

Migracja: istniejące Gate nie zmieniają zachowania; aby używać przywracania,
composition root musi utworzyć LocalVaultGate osobno dla sesji/upstreamu oraz
wdrożyć validate_local_arguments bez logowania plaintextu. Nie ma gotowego CLI,
SQLite ani izolowanego runnera. Nie dodajemy fallbacku obchodzącego te granice.
