BIN_RECORD_TYPES = {
    0x0A: 'Linia',
    0x41: 'Stopka',
    0x42: 'Raport dobowy (biletowy)',
    0x44: 'Nagłówek dokumentu',
    0x46: 'Linie informacyjne w fakturze',
    0x47: 'Identyfikator podatnika (faktura)',
    0x48: 'Nagłówek wydruku',
    0x49: 'Dane z grafiką',
    0x4A: 'Sprzedaż faktury',
    0x4C: 'Sprzedaż biletu',
    0x4D: 'Rozpoczęcie biletu',
    0x4E: 'Zakończenie biletu',
    0x4F: 'Rabat/narzut do paragonu',
    0x50: 'Promocja',
    0x51: 'Zaliczka do faktury',
    0x52: 'Rabat/narzut do faktury',
    0x53: 'Separator tekstów',
    0x54: 'Tekst nagłówka',
    0x55: 'Ulga do biletu',
    0x56: 'Zaliczka',
    0x58: 'Dodatkowe linie w stopce',
    0x59: 'Numer systemowy',
    0x5A: 'Grafika BMP',
    0x61: 'Sprzedaż',
    0x62: 'Kody kreskowe',
    0x63: 'Opakowanie',
    0x64: 'Podsumowanie opakowań',
    0x65: 'Sekcja',
    0x69: 'Skrót do grafiki',
    0x6A: 'Płatność formą płatności',
    0x6B: 'Reszta formą płatności',
    0x6C: 'Teksty informacyjne ze stopki',
    0x6D: 'Podpis SHA dokumentu',
    0x6E: 'Podsumowanie rabatów/narzutów',
    0x70: 'Raport dobowy',
    0x72: 'Przeliczanie walut',
    0x73: 'Suma w walucie ewidencyjnej',
    0x74: 'Podpis dokumentu (RSA2048)',
    0x75: 'Rabat/narzut do pozycji',
    0x76: 'Podsumowanie sprzedaży VAT',
    0x78: 'Płatność walutą',
    0x79: 'Reszta walutą',
    0x7A: 'Nieznany',
    0x80: 'Typ zdarzenia',
    0x81: 'Zmiana stawek VAT',
    0x82: 'Zmiana daty/czasu',
    0x83: 'Zmiana waluty',
    0x84: 'Zmiana konfiguracji serwera',
    0x85: 'Zmiana firmware',
    0x86: 'Tryb serwisowy',
    0x87: 'Oznaczenie pamięci chronionej',
    0x88: 'Id serwisanta',
    0x89: 'Źródło aktualizacji',
    0x8A: 'Klucz publiczny',
    0x8B: 'Punkt sprzedaży',
    0x8C: 'Zmiana harmonogramu',
    0x8D: 'Zmiana QRCode',
    0x8E: 'Klucz publiczny kasy',
    0x8F: 'Wysłanie certyfikatów',
    0xA1: 'Metoda kasowa',
    0xA2: 'Samofakturowanie',
    0xA3: 'Odwrotne obciążenie',
    0xA4: 'Zwolnienie z podatku',
    0xA5: 'Egzekucja',
    0xA6: 'Przedstawiciel',
    0xA7: 'Transport',
    0xA8: 'Transakcja trójstronna',
    0xA9: 'Usługi turystyczne',
    0xAA: 'Towary inne',
    0xB1: 'Informacje o kupującym',
    0xB2: 'Podsumowanie faktury',
    0xB3: 'Numer faktury',
    0xB4: 'Nazwa faktury',
    0xB5: 'Sekcja przed towarami',
    0xB7: 'Suma kontrolna poprzedniego dokumentu',
    0xB8: 'JPKID poprzedniego dokumentu',
    0xC0: 'Dane JWS',
    0xC1: 'Kod weryfikacyjny paragonu',
    0xC2: 'Dane JPK',
    0xC3: 'Dane loterii paragonowej',
    0xD0: 'Numer slotu grafiki',
    0xD1: 'Raport fiskalizacji',
    0x20: 'Podpis RSA512',
    0xE0: 'Opis biletu',
    0xE1: 'Trasa biletu',
    0xE2: 'Kurs biletu',
    0xE3: 'Nazwa pasażera',
    0xE4: 'Port docelowy',
    0xE5: 'Port przesiadkowy',
}


def print_bin_file_structure(fsp, bin_path):
    """
    Pobiera plik BIN przez FSP, parsuje rekordy i wypisuje ich typy oraz rozmiary.
    Dla rekordu 0x44 (Nagłówek dokumentu) rozpoznaje typ dokumentu.
    """
    DOC_TYPE_MAP = {
        0x00: 'Zwykły dokument',
        0x01: 'Paragon',
        0x02: 'Faktura',
        0x03: 'Raport dobowy',
        0x04: 'Raport fiskalny',
    }
    data = fsp.read_file_fsp(bin_path)
    if not data:
        print(f"Brak pliku {bin_path} lub plik pusty!")
        return
    print(f"Struktura pliku {bin_path}:")
    offset = 0
    idx = 0
    doc_type_found = False
    while offset + 6 <= len(data):
        reserved = int.from_bytes(data[offset:offset+2], 'big')
        rec_type = int.from_bytes(data[offset+2:offset+4], 'big')
        rec_size = int.from_bytes(data[offset+4:offset+6], 'big')
        type_name = BIN_RECORD_TYPES.get(rec_type, f'Nieznany (0x{rec_type:02X})')
        extra = ""
        # Jeśli to nagłówek dokumentu, spróbuj rozpoznać typ dokumentu
        if rec_type == 0x44 and not doc_type_found and rec_size > 6:
            doc_type_byte = data[offset+6]
            doc_type = DOC_TYPE_MAP.get(doc_type_byte, f'Nieznany typ ({doc_type_byte})')
            extra = f" [typ dokumentu: {doc_type}]"
            doc_type_found = True
        print(f"  Rekord {idx}: typ=0x{rec_type:02X} ({type_name}), rozmiar={rec_size}{extra}")
        offset += rec_size
        idx += 1
        if rec_size == 0:
            break
    if offset < len(data):
        print(f"  Pozostało {len(data)-offset} bajtów na końcu pliku (nieprzetworzonych)")
    return

import struct
import re

def parse_medium_dat(data: bytes):
    fmt = '>HLL14sL14s10sH'
    size = struct.calcsize(fmt)
    if len(data) < size:
        raise ValueError("Plik medium.dat jest za krótki!")
    unpacked = struct.unpack(fmt, data[:size])
    return {
        'wersja_pliku': unpacked[0],
        'id_urzadzenia': hex(unpacked[1]),
        'nr_nosnika': unpacked[2],
        'prefix_nr_urzadzenia': unpacked[3].decode('ascii', errors='ignore').rstrip('\x00'),
        'nr_pierwszego_dokumentu': hex(unpacked[4]),
        'nr_ewidencyjny': unpacked[5].decode('ascii', errors='ignore').rstrip('\x00'),
        'nip': unpacked[6].decode('ascii', errors='ignore').rstrip('\x00'),
        'tryb_pracy': unpacked[7],
    }

def print_medium_dat_info(fsp):
    DEVICE_ID_MAP = {
        0x00000066: "Thermal HD Online 2.01",
        0x00000067: "Thermal XL2 Online 2.01",
        0x00000069: "Trio Online 1.02",
        0x0000006A: "Pospay Online 1.01",
        0x0000006B: "Vero 2.01",
        0x0000006C: "Thermal HX Online 1.01",
        0x0000006D: "Thermal XL2 S Online 2.01",
        0x0000006E: "Thermal HX S Online 1.01",
        0x0000006F: "Evo 1.01",
        0x00000070: "Thermal XL2 B 1.01",
        0x00000071: "Thermal XL2 W 1.01",
        0x00000072: "Fawag Box 1.01",
        0x00000073: "Temo Online 2.01",
        0x00000074: "Trio Online 2.01",
        0x00000075: "Pospay Online 2.01",
    }
    try:
        data = fsp.read_file_fsp('EJ0/medium.dat')
        if not data:
            print("Brak pliku medium.dat!")
            return None
        info = parse_medium_dat(data)
        raw_id = info.get('id_urzadzenia')
        if raw_id is not None:
            try:
                id_int = int(raw_id, 16)
            except Exception:
                id_int = None
        else:
            id_int = None
        model = DEVICE_ID_MAP[id_int] if id_int in DEVICE_ID_MAP else "Nieznany model"
        print("--- medium.dat ---")
        print("model_drukarki:", model)
        for k, v in info.items():
            print(f"{k}: {v}")
        return info
    except Exception as e:
        print("Błąd odczytu medium.dat:", e)
        return None

def print_key_der_info(fsp):
    try:
        data = fsp.read_file_fsp('EJ0/KEY.DER')
        if not data:
            print("Brak pliku KEY.DER!")
            return
        print(f"KEY.DER: {len(data)} bajtów (klucz publiczny DER)")
    except Exception as e:
        print(f"Błąd odczytu KEY.DER: {e}")


def detect_doc_type(fsp, bin_path):
    """Pobierz pierwsze bajty pliku BIN i spróbuj rozpoznać typ dokumentu (rekord 0x44)."""
    DOC_TYPE_MAP = {
        0x00: 'Zwykły dokument',
        0x01: 'Paragon',
        0x02: 'Faktura',
        0x03: 'Raport dobowy',
        0x04: 'Raport fiskalny',
    }
    try:
        # Pobierz tylko pierwszy fragment pliku (offset 0) — get_file powinien zwrócić pierwszy segment
        data = fsp.get_file(f"{bin_path}", 0)
        if not data:
            return None
        offset = 0
        while offset + 6 <= len(data):
            rec_type = int.from_bytes(data[offset+2:offset+4], 'big')
            rec_size = int.from_bytes(data[offset+4:offset+6], 'big')
            if rec_type == 0x44 and rec_size > 6 and offset + 6 < len(data):
                doc_type_byte = data[offset+6]
                return DOC_TYPE_MAP.get(doc_type_byte, f'Nieznany typ ({doc_type_byte})')
            if rec_size <= 0:
                break
            offset += rec_size
        return None
    except Exception:
        return None

def list_all_bin_sig_files(fsp, start_dir="EJ0/DOC"):
    found_files = []
    try:
        entries = fsp.list_directory(start_dir)
    except Exception as e:
        print(f"Błąd listowania {start_dir}: {e}")
        return found_files
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get('is_dir'):
            found_files.extend(list_all_bin_sig_files(fsp, f"{start_dir}/{entry['name']}"))
        else:
            name = entry.get('name', '').upper()
            if re.match(r'^[0-9]{8}\.BIN$', name) or name.endswith('.SIG'):
                found_files.append(f"{start_dir}/{entry['name']}")
    return found_files
import argparse
import logging
import signal
import os
from printer_communication import PrinterCommunicator
import storage

def find_bin_files(client, path, depth=0):
    """
    Rekurencyjnie przeszukuje katalog podany w path w poszukiwaniu plików BIN i SIG.
    """
    bin_files = []
    try:
        entries = client.list_directory(path)
    except Exception:
        return bin_files
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get('is_dir') or entry.get('type') == 1:
            # Rekurencja do podkatalogu
            bin_files.extend(find_bin_files(client, f"{path}/{entry['name']}", depth+1))
        else:
            if entry['name'].upper().endswith('.BIN') or entry['name'].upper().endswith('.SIG'):
                bin_files.append(f"{path}/{entry['name']}")
    return bin_files

def main():
    pass

    parser = argparse.ArgumentParser(description="Odczyt danych z drukarki POSNET XL2 Online (FSP)")
    parser.add_argument('--ip', required=True, help='IP drukarki')
    parser.add_argument('--nr', required=True, help='Numer drukarki')
    parser.add_argument('--port', type=int, default=2121, help='Port (domyślnie 2121)')
    parser.add_argument('--start-dir', default='EJ0', help='Katalog startowy (domyślnie EJ0)')
    parser.add_argument('--start-index', type=int, help='Numer pliku BIN od którego zacząć (np. 45 dla 00000045.BIN)')
    parser.add_argument('--page-size', type=int, default=4096, help='Preferowany rozmiar paginacji GET_DIR (domyślnie 4096)')
    args = parser.parse_args()

    # preferowany rozmiar strony paginacji ustawiany z argumentu CLI
    page_size_pref = args.page_size

    def list_directory_full_paged(fsp, path, page_size=page_size_pref):
        """
        Pobierz wszystkie wpisy z katalogu FSP z paginacją (iteruje po offsetach aż do RDTYPE_END)
        """
        all_entries = []
        position = 0
        while True:
            entries, found_end = fsp.list_directory(path, position, preferred_size=page_size)
            if not entries:
                break
            all_entries.extend(entries)
            if found_end:
                break
            position += len(entries)
        return all_entries

    arch_dir = os.path.join(os.path.dirname(__file__), 'arch')
    os.makedirs(arch_dir, exist_ok=True)

    # Ustaw poziom logowania modułów FSP/printer, aby ukryć INFO/DEBUG z biblioteki
    logging.getLogger('fsp_client').setLevel(logging.WARNING)
    logging.getLogger('printer_communication').setLevel(logging.WARNING)

    communicator = PrinterCommunicator(
        ip_address=args.ip,
        printer_number=args.nr,
        port=args.port,
        protocol='udp'
    )

    # Zarejestruj handler sygnałów aby wysłać CC_BYE przy Ctrl+C / kill
    def _graceful_close(signum, frame):
        try:
            communicator.fsp.close()
        except Exception:
            pass
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _graceful_close)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, _graceful_close)

    # Spróbuj zakończyć ewentualnie wiszącą sesję FSP
    try:
        communicator.fsp.close()
    except Exception:
        pass

    # Najpierw podstawowe informacje — i sprawdź czy drukarka jest fiskalizowana
    medium_info = print_medium_dat_info(communicator.fsp)
    print_key_der_info(communicator.fsp)
    if not medium_info:
        print("Nie można odczytać medium.dat — przerywam.")
        try:
            communicator.fsp.close()
        except Exception:
            pass
        return
    prefix = medium_info.get('prefix_nr_urzadzenia')
    if not prefix:
        print("Drukarka nie jest fiskalizowana (brak prefiksu urządzenia). Przerywam.")
        try:
            communicator.fsp.close()
        except Exception:
            pass
        return
    # Pokaż potwierdzenie filtrowania jeśli podano start-index
    if args.start_index is not None:
        print(f"Filtrowanie plików od indeksu: {args.start_index}")

    # Lokalne miejsce zapisu surowych plików
    local_root = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(local_root, exist_ok=True)

    # Skanuj rekurencyjnie katalog DOC i wypisuj pliki natychmiast po znalezieniu
    doc_root = f"{args.start_dir}/DOC"

    # start_idx lokalnie
    start_idx = args.start_index if args.start_index is not None else None
    # when provided, start_parts holds the target A/BB/CC numeric path to begin scanning from
    start_parts = None
    # flag set when we've reached the start-path during traversal
    started = False

    # Jeśli podano start-index, wylicz katalog startowy na podstawie numeracji plików
    # struktura: DOC/<A>/<BB>/<CC>/000NNNNN.BIN, gdzie:
    # A = idx // 1000000
    # BB = (idx // 10000) % 100
    # CC = (idx // 100) % 100
    if start_idx is not None:
        try:
            idx = int(start_idx)
            A = idx // 1000000
            BB = (idx // 10000) % 100
            CC = (idx // 100) % 100
            sub = f"{A}/{BB:02d}/{CC:02d}"
            # keep doc_root as the DOC root but remember the start-subfolder parts
            print(f"Start-index podany: {start_idx} -> zaczynam skan od katalogu: {doc_root}/{sub}")
            # use the exact start index so we begin from that file within the folder
            start_idx = idx
            start_parts = [int(A), int(BB), int(CC)]
        except Exception:
            pass

    if args.page_size:
        print(f"Używany preferowany rozmiar strony (GET_DIR preferred_size): {args.page_size}")

    stats = {'found': 0, 'skipped': 0, 'saved': 0}

    def gather_and_print(path):
        nonlocal started
        print(f"Scanning: {path}")
        # flush to ensure immediate output
        try:
            import sys; sys.stdout.flush()
        except Exception:
            pass
        try:
            entries = list_directory_full_paged(communicator.fsp, path)
        except Exception:
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get('name')
            if entry.get('is_dir') or entry.get('type') == 1:
                # if a start_parts was provided and we haven't reached it yet,
                # decide whether this directory (and its subtree) is before/after the start-path
                if start_parts and not started:
                    # compute relative parts from doc_root
                    if path == doc_root:
                        rel_parts = []
                    elif path.startswith(doc_root + '/'):
                        rel = path[len(doc_root) + 1:]
                        rel_parts = rel.split('/') if rel else []
                    else:
                        rel_parts = []
                    prospective = rel_parts + [name]
                    # build numeric comparison list (A,BB,CC)
                    comp = []
                    for i in range(3):
                        if i < len(prospective):
                            try:
                                comp.append(int(prospective[i]))
                            except Exception:
                                comp.append(-1)
                        else:
                            comp.append(-1)
                    # compare lexicographically to start_parts
                    skip = False
                    for p, s in zip(comp, start_parts):
                        if p < s:
                            skip = True
                            break
                        elif p > s:
                            # this subtree is after start; mark started and descend
                            started = True
                            break
                        # else equal -> continue to next part
                    if skip:
                        continue
                gather_and_print(f"{path}/{name}")
            else:
                if not name:
                    continue
                up = name.upper()
                if not (up.endswith('.BIN') or up.endswith('.SIG')):
                    continue
                # jeśli podano start_index, filtruj na żywo
                if start_idx is not None:
                    try:
                        num = int(name.split('.')[0])
                        if num < start_idx:
                            stats['skipped'] += 1
                            # skip older files
                            continue
                    except Exception:
                        pass
                _, ext = os.path.splitext(name)
                ext = ext.upper().lstrip('.')
                doc_type = None
                if ext == 'BIN':
                    try:
                        doc_type = detect_doc_type(communicator.fsp, f"{path}/{name}")
                    except Exception:
                        doc_type = None
                extra = f" - {doc_type}" if doc_type else ""
                # Zapisz kopię surową lokalnie (BIN i SIG)
                saved = None
                try:
                    saved = storage.save_file_from_fsp(communicator.fsp, f"{path}/{name}", local_root, args.nr, prefix)
                except Exception:
                    saved = None
                if saved:
                    stats['saved'] += 1
                    stats['found'] += 1
                    print(f"{path}/{name} - {ext}{extra} -> saved: {saved['saved_path']} (sha256:{saved['sha256']})")
                else:
                    stats['found'] += 1
                    print(f"{path}/{name} - {ext}{extra} -> not saved")

    # Wypisz pliki w trybie online (streaming)
    try:
        if start_parts:
            # start from computed subfolder and then continue to next numbered subfolders
            current_idx = start_idx if start_idx is not None else 0
            while True:
                A = current_idx // 1000000
                BB = (current_idx // 10000) % 100
                CC = (current_idx // 100) % 100
                sub = f"{A}/{BB:02d}/{CC:02d}"
                target = f"{doc_root}/{sub}"
                print(f"Scanning: {target}")
                prev_found = stats['found']
                try:
                    gather_and_print(target)
                except Exception:
                    pass
                # if this folder contributed no files, assume we've reached the end
                if stats['found'] == prev_found:
                    break
                current_idx += 100
        else:
            gather_and_print(doc_root)
        # po zakończeniu pokaż krótkie statystyki
        print(f"Skanowanie zakończone. Znaleziono: {stats['found']} (pobrano/zapisano: {stats['saved']}), odrzucono (przed start-index): {stats['skipped']}")
    finally:
        try:
            communicator.fsp.close()
        except Exception:
            pass
    return

if __name__ == '__main__':
    main()
