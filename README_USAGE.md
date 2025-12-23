# Instrukcja obsługi - skrócona (format dla Gita)

Poniżej krótkie polecenia i opis działania skryptów w repozytorium. Skrypt `find_packaging.py` został przeniesiony do katalogu głównego.

## 1. Pobieranie danych
- Uruchom `main.py` (zbieranie z drukarek). Opcjonalnie możesz podać `--start-index` jeśli chcesz rozpocząć od konkretnego rekordu:

```powershell
python main.py --start-index 100
```

- Dane są zapisywane w `data/<lokal>/<printer>/...` jako pliki `.BIN`, `.SIG` i pliki metadanych `.meta.json`.

## 2. Przegląd pojedynczego pliku BIN
- Użyj `inspect_bin.py` i podaj pełną ścieżkę do pliku BIN jako argument:

```powershell
python inspect_bin.py data/1/EAO\ 2402438095/EJ0/DOC/0/00/00/00000019.BIN
```

- Skrypt wypisze nagłówek dokumentu, pozycje, opakowania (kaucje), podsumowania i podpisy.

## 3. Wyszukiwanie kaucji (bez agregacji)
- Skrypt `find_packaging.py` (katalog główny) szuka opakowań i wypisuje tabelę z wierszami:

```powershell
python find_packaging.py data
```

- Wyjście (tabela): `location, printer, file, doc_number, timestamp, pack_name, qty, value, total`.
- Flagi:
  - `--all` — pokaż też wiersze bez rozpoznanej nazwy opakowania
  - `--csv` — wypisz wynik w formacie CSV zamiast tabeli w terminalu

## 4. Wyszukiwanie kaucji (z agregacją)
- Aby zobaczyć podsumowanie pogrupowane po lokalu i drukarce:

```powershell
python find_packaging.py data --aggregate
```

- Wyjście (tabela): `location, printer, pack_name, rows, returns, issued, sum_total`.
- Możesz zapisać wynik do pliku CSV:

```powershell
python find_packaging.py data --aggregate --csv > packaging_aggregate.csv
```

## 5. Krótkie wyjaśnienie mechanizmu wykrywania kaucji
- Preferujemy strukturalny rekord `0x63` (jeśli występuje) — daje nazwę, ilość i kwoty w formie binarnej.
- Jeśli brak 0x63, sprawdzamy linie tekstowe (rekord `0x0A`) i heurystycznym regexem próbujemy wyciągnąć `nazwa qty x cena total`.
- Agregacja normalizuje nazwy (`NFKC`) i grupuje po `location` → `printer` → `pack_name`.

## 6. Przykłady (terminal)
- Bez agregacji (szczegóły):

```
python find_packaging.py data
file          doc_number  timestamp            pack_name     qty  value  total
00000019.BIN           9  2025-12-08T07:50:43  kaucja szkło  1.0    1.0    1.0
00000021.BIN          11  2025-12-08T07:52:40  kaucja szkło  1.0    1.0   -1.0
```

- Z agregacją:

```
python find_packaging.py data --aggregate
location  printer         pack_name     rows  returns  issued  sum_total
1         EAO 2402438095  kaucja szkło     8        1       7       5.50
```

---

Plik ten nadaje się do umieszczenia w repozytorium (commit). Jeśli chcesz, mogę:
- dodać `--start-index` do `main.py` jeśli obecnie nie obsługuje, 
- zaktualizować instrukcje, gdy przeniesiesz inne skrypty.

***
Plik wygenerowany automatycznie przez narzędzie pomocnicze — umieść go w repo i zatwierdź zmianę (`git add README_USAGE.md && git commit -m "Add usage guide"`).
