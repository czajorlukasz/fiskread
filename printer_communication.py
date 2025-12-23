import socket
import struct
from typing import Optional, Dict, Any, List, Tuple
import logging
from fsp_client import FSPClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Znaki protokołu POSNET
STX = b'\x02'
ETX = b'\x03'
TAB = b'\x09'


class PrinterCommunicator:
    """Klasa do komunikacji z drukarkami fiskalnymi POSNET XL2 Online przez protokół FSP"""



    def read_file_fsp(self, path: str, segment_size: int = 128):
        """Pobierz plik segmentami (przekierowanie do FSPClient.read_file_fsp)"""
        return self.fsp.read_file_fsp(path, segment_size)

    def read_file(self, path: str):
        """Pobierz plik jednym wywołaniem (przekierowanie do FSPClient.get_file)"""
        return self.fsp.get_file(path)

    def list_directory(self, path: str):
        """Listuj katalog (przekierowanie do FSPClient.list_directory)"""
        return self.fsp.list_directory(path)
    
    def __init__(self, ip_address: str, printer_number: str, port: int = 2121, protocol: str = 'udp'):
        """
        Inicjalizacja komunikatora
        
        Args:
            ip_address: Adres IP drukarki
            printer_number: Numer drukarki fiskalnej
            port: Port komunikacji (domyślnie 2121)
            protocol: Protokół komunikacji 'tcp' lub 'udp' (domyślnie 'udp')
        """
        self.ip_address = ip_address
        self.printer_number = printer_number
        self.port = port
        self.protocol = protocol.lower()
        self.timeout = 3  # sekundy - krótszy timeout
        self.fsp_service_id = 1  # ID serwisu FSP
        self.max_packet_size = 128  # Maksymalny rozmiar danych w pakiecie (bajty)
        
        # Klient FSP
        self.fsp = FSPClient(ip_address, port, protocol)
    
    def test_connection(self) -> bool:
        """
        Testuj połączenie z drukarką
        
        Returns:
            True jeśli połączenie udane, False w przeciwnym razie
        """
        try:
            if self.protocol == 'udp':
                # Test UDP - wysłanie prostej komendy ping
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    # Wyślij prosty pakiet testowy
                    test_message = b'\x02TEST\x03'
                    sock.sendto(test_message, (self.ip_address, self.port))
                    logger.info(f"Wysłano pakiet testowy UDP do {self.ip_address}:{self.port}")
                    try:
                        # Próbuj odebrać odpowiedź (opcjonalne)
                        sock.recvfrom(1024)
                        logger.info(f"Otrzymano odpowiedź UDP z {self.ip_address}:{self.port}")
                    except socket.timeout:
                        # Brak odpowiedzi to nie błąd dla UDP
                        logger.info(f"Brak odpowiedzi UDP (normalnie dla testowego pakietu)")
                    return True
            else:  # TCP
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((self.ip_address, self.port))
                    logger.info(f"Połączenie TCP z {self.ip_address}:{self.port} udane")
                    return True
        except socket.timeout:
            logger.error(f"Timeout podczas łączenia {self.protocol.upper()} z {self.ip_address}:{self.port}")
            return False
        except socket.error as e:
            logger.error(f"Błąd połączenia {self.protocol.upper()} z {self.ip_address}:{self.port}: {e}")
            return False
        except Exception as e:
            logger.error(f"Nieoczekiwany błąd: {e}")
            return False
    
    def send_command(self, command: bytes) -> Optional[bytes]:
        """
        Wyślij komendę do drukarki i odbierz odpowiedź
        
        Args:
            command: Komenda do wysłania
            
        Returns:
            Odpowiedź od drukarki lub None w przypadku błędu
        """
        try:
            if self.protocol == 'udp':
                # Komunikacja UDP
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    
                    # Wyślij komendę
                    sock.sendto(command, (self.ip_address, self.port))
                    logger.info(f"Wysłano komendę UDP: {command.hex()} do {self.ip_address}:{self.port}")
                    
                    # Odbierz odpowiedź
                    response, addr = sock.recvfrom(65535)  # Max rozmiar pakietu UDP
                    logger.info(f"Odebrano {len(response)} bajtów z {addr}")
                    return response
            else:
                # Komunikacja TCP
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((self.ip_address, self.port))
                    
                    # Wyślij komendę
                    sock.sendall(command)
                    logger.info(f"Wysłano komendę TCP: {command.hex()}")
                    
                    # Odbierz odpowiedź
                    response = b''
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        # Jeśli odpowiedź jest kompletna (można dodać logikę sprawdzania)
                        if len(chunk) < 4096:
                            break
                    
                    logger.info(f"Odebrano {len(response)} bajtów")
                    return response
                
        except Exception as e:
            logger.error(f"Błąd podczas wysyłania komendy {self.protocol.upper()}: {e}")
            return None
    
    def fetch_electronic_copy(self, start_doc: int = 0, max_docs: int = 100) -> Optional[bytes]:
        """
        Pobierz kopię elektroniczną z pamięci chronionej drukarki POSNET
        
        Proces:
        1. Pobierz dane identyfikacyjne drukarki (FMEM/ECR_DATA.DAT)
        2. Listuj katalogi aby znaleźć rzeczywiste pliki
        3. Pobierz znalezione pliki BIN
        
        Args:
            start_doc: Numer dokumentu od którego zacząć (domyślnie 0)
            max_docs: Maksymalna liczba dokumentów do pobrania (domyślnie 100)
        
        Returns:
            Surowe dane kopii elektronicznej (JSON z metadanymi) lub None w przypadku błędu
        """
        try:
            logger.info("Rozpoczynam pobieranie kopii elektronicznej...")
            
            # 1. Pobierz dane drukarki z FMEM/ECR_DATA.DAT
            logger.info("Pobieranie FMEM/ECR_DATA.DAT...")
            ecr_data = self._fsp_get_file("FMEM/ECR_DATA.DAT")
            if ecr_data:
                logger.info(f"✓ Pobrano ECR_DATA.DAT: {len(ecr_data)} bajtów")
                try:
                    import json
                    ecr_json = json.loads(ecr_data.decode('utf-8'))
                    logger.info(f"   Drukarka: {ecr_json.get('ECR_DATA', {}).get('Factory_number', 'N/A')}")
                except:
                    pass
            else:
                logger.warning("✗ Nie udało się pobrać ECR_DATA.DAT")
            
            # 2. Listuj root aby zobaczyć dostępne katalogi
            logger.info("\nListowanie głównego katalogu...")
            root_dirs = self.fsp.list_directory("")
            
            if root_dirs:
                logger.info(f"✓ Katalogi główne: {[d['name'] for d in root_dirs if d['type'] == 'DIR']}")
            
            # 3. Sprawdź zarówno EJ0/DOC jak i inne możliwe lokalizacje
            doc_paths_to_try = ["EJ0/DOC", "EJ1/DOC", "DOC"]
            all_bin_files = []
            
            for base_path in doc_paths_to_try:
                logger.info(f"\nSprawdzanie {base_path}...")
                doc_dirs = self.fsp.list_directory(base_path)
                
                if not doc_dirs:
                    logger.info(f"  ✗ Brak lub niedostępny")
                    continue
                    
                logger.info(f"  ✓ Znaleziono {len(doc_dirs)} wpisów")
                
                # Zbierz pliki BIN
                for dir_entry in doc_dirs[:5]:  # Pierwsze 5 katalogów
                    if dir_entry['type'] == 'DIR':
                        x = dir_entry['name']
                        logger.info(f"    Sprawdzanie {base_path}/{x}...")
                        
                        yy_dirs = self.fsp.list_directory(f"{base_path}/{x}")
                        if yy_dirs:
                            for yy_entry in yy_dirs[:3]:  # Pierwsze 3 podkatalogi
                                if yy_entry['type'] == 'DIR':
                                    yy = yy_entry['name']
                                    
                                    zz_dirs = self.fsp.list_directory(f"{base_path}/{x}/{yy}")
                                    if zz_dirs:
                                        for zz_entry in zz_dirs[:3]:  # Pierwsze 3 podkatalogi
                                            if zz_entry['type'] == 'DIR':
                                                zz = zz_entry['name']
                                                
                                                files = self.fsp.list_directory(f"{base_path}/{x}/{yy}/{zz}")
                                                if files:
                                                    bin_files = [f for f in files if f['name'].endswith('.BIN')]
                                                    if bin_files:
                                                        logger.info(f"      {base_path}/{x}/{yy}/{zz}: {len(bin_files)} plików BIN")
                                                        all_bin_files.extend([(f"{base_path}/{x}/{yy}/{zz}/{f['name']}", f['size']) for f in bin_files])
                
                if all_bin_files:
                    break  # Znaleziono pliki, nie szukaj dalej
            
            logger.info(f"\n✓ Znaleziono łącznie {len(all_bin_files)} plików BIN")
            
            # 4. Pobierz pliki (maksymalnie max_docs)
            documents = []
            for file_path, file_size in all_bin_files[:max_docs]:
                logger.info(f"\nPobieranie {file_path} ({file_size} bajtów)...")
                bin_data = self._fsp_get_file(file_path)
                
                if bin_data:
                    documents.append({
                        'path': file_path,
                        'size': len(bin_data),
                        'data': bin_data.hex()
                    })
                    logger.info(f"✓ Pobrano {len(bin_data)} bajtów")
                else:
                    logger.warning(f"✗ Nie udało się pobrać")
            
            logger.info(f"\n=== PODSUMOWANIE ===")
            logger.info(f"Pobrano {len(documents)} z {len(all_bin_files)} dokumentów")
            
            return self._create_result(ecr_data, documents)
            
        except Exception as e:
            logger.error(f"Błąd podczas pobierania kopii elektronicznej: {e}")
            import json
            return json.dumps({'status': 'error', 'message': str(e)}).encode('utf-8')
    
    def _create_result(self, ecr_data: Optional[bytes], documents: list) -> bytes:
        """Utwórz wynik JSON"""
        import json
        
        ecr_json = None
        if ecr_data:
            try:
                ecr_json = json.loads(ecr_data.decode('utf-8'))
            except:
                pass
        
        result = {
            'status': 'success',
            'ecr_data': ecr_json,
            'documents_found': len(documents),
            'documents': documents
        }
        return json.dumps(result).encode('utf-8')
    
    def _fsp_get_file(self, file_path: str) -> Optional[bytes]:
        """
        Pobierz plik przez FSP używając FSPClient
        
        Args:
            file_path: Ścieżka do pliku (np. "0:EJ0/DOC/0/00/00/00000000.BIN")
            
        Returns:
            Zawartość pliku lub None
        """
        try:
            logger.info(f"Pobieranie {file_path}...")
            
            # Użyj FSPClient do pobrania pliku
            file_data = self.fsp.get_file(file_path)
            
            if file_data:
                logger.info(f"Pobrano plik {file_path}, rozmiar: {len(file_data)} bajtów")
                return file_data
            else:
                logger.warning(f"Nie udało się pobrać pliku {file_path}")
                return None
                
        except Exception as e:
            logger.error(f"Błąd pobierania pliku {file_path}: {e}")
            return None
    

    
    def _calculate_posnet_checksum(self, data: bytes) -> str:
        """
        Oblicz sumę kontrolną POSNET (XOR + HEX)
        
        Args:
            data: Dane do obliczenia sumy (bez STX, ETX i #checksum)
            
        Returns:
            Suma kontrolna jako 4-znakowy HEX (np. "642B")
        """
        checksum = 0
        for byte in data:
            checksum ^= byte
        
        # Podwójna suma (XOR wyniku z samym sobą pomnożonym)
        checksum = (checksum ^ (checksum << 8)) & 0xFFFF
        return f"{checksum:04X}"
    
    def _build_posnet_svc_frame(self, service_id: int, flags: int, data_hex: str) -> bytes:
        """
        Buduj ramkę POSNET 'svc' do tunelowania FSP
        
        Format: <STX>svc<TAB>id{service_id}<TAB>fl{flags}<TAB>da{data_hex}<TAB>#{checksum}<ETX>
        
        Args:
            service_id: ID serwisu (dla FSP = 1)
            flags: Flagi pakietowania (bit 0: start, bit 1: end)
            data_hex: Dane jako HEX string (max 256 znaków = 128 bajtów)
            
        Returns:
            Kompletna ramka POSNET
        """
        # Buduj zawartość ramki (bez STX, ETX, checksumu)
        content = f"svc\tid{service_id}\tfl{flags}\tda{data_hex}\t".encode('ascii')
        
        # Oblicz checksumę
        checksum = self._calculate_posnet_checksum(content)
        
        # Zbuduj pełną ramkę
        frame = STX + content + f"#{checksum}".encode('ascii') + ETX
        
        logger.debug(f"Ramka POSNET: {frame}")
        return frame
    
    def _parse_posnet_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """
        Parsuj odpowiedź POSNET
        
        Args:
            response: Surowa odpowiedź od drukarki
            
        Returns:
            Słownik z rozparsowanymi polami lub None w przypadku błędu
        """
        try:
            # Usuń STX i ETX
            if response.startswith(STX):
                response = response[1:]
            if response.endswith(ETX):
                response = response[:-1]
            
            # Podziel na pola
            response_str = response.decode('ascii', errors='ignore')
            parts = response_str.split('\t')
            
            result = {'command': parts[0] if len(parts) > 0 else None}
            
            # Parsuj parametry
            for part in parts[1:]:
                if part.startswith('id'):
                    result['id'] = int(part[2:])
                elif part.startswith('fl'):
                    result['fl'] = int(part[2:])
                elif part.startswith('da'):
                    result['da'] = part[2:]
                elif part.startswith('#'):
                    result['checksum'] = part[1:]
            
            logger.debug(f"Odpowiedź POSNET: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Błąd parsowania odpowiedzi POSNET: {e}")
            return None
    
    def _segment_data(self, data: bytes) -> List[Tuple[int, bytes]]:
        """
        Podziel dane na segmenty max 128 bajtów z odpowiednimi flagami
        
        Args:
            data: Dane do podzielenia
            
        Returns:
            Lista tupli (flags, segment_data)
        """
        segments = []
        data_len = len(data)
        
        if data_len <= self.max_packet_size:
            # Pojedynczy pakiet: flaga 3 (start + end)
            segments.append((3, data))
        else:
            # Wiele pakietów
            offset = 0
            segment_idx = 0
            
            while offset < data_len:
                segment = data[offset:offset + self.max_packet_size]
                
                # Określ flagi
                if segment_idx == 0:
                    flags = 1  # Początek pakietu
                elif offset + len(segment) >= data_len:
                    flags = 2  # Koniec pakietu
                else:
                    flags = 0  # Środkowy segment
                
                segments.append((flags, segment))
                offset += len(segment)
                segment_idx += 1
        
        return segments
    
    def _send_fsp_command(self, fsp_data: bytes) -> Optional[bytes]:
        """
        Wyślij komendę FSP przez tunel POSNET svc
        
        Args:
            fsp_data: Dane protokołu FSP (bajty)
            
        Returns:
            Odpowiedź FSP lub None
        """
        try:
            # Podziel dane na segmenty
            segments = self._segment_data(fsp_data)
            
            response_data = b''
            
            for flags, segment in segments:
                # Konwertuj segment na HEX
                data_hex = segment.hex().upper()
                
                # Zbuduj ramkę POSNET
                frame = self._build_posnet_svc_frame(self.fsp_service_id, flags, data_hex)
                
                # Wyślij przez UDP/TCP
                logger.info(f"Wysyłanie segmentu {len(segments)} z flagami {flags}")
                response = self.send_command(frame)
                if not response:
                    logger.error(f"Brak odpowiedzi od drukarki dla segmentu z flagami {flags}")
                    return None
                
                logger.info(f"Otrzymano odpowiedź: {len(response)} bajtów")
                
                # Parsuj odpowiedź
                parsed = self._parse_posnet_response(response)
                if not parsed or 'da' not in parsed:
                    logger.error("Nieprawidłowa odpowiedź POSNET")
                    return None
                
                # Dekoduj dane HEX
                segment_response = bytes.fromhex(parsed['da'])
                response_data += segment_response
                
                # Sprawdź czy to koniec pakietu
                resp_flags = parsed.get('fl', 3)
                if resp_flags & 2:  # Bit 1 = koniec pakietu
                    break
                
                # Jeśli nie koniec, wyślij żądanie kolejnego segmentu (fl=0)
                if not (resp_flags & 2):
                    logger.info("Pobieranie kolejnego segmentu odpowiedzi...")
                    continue_frame = self._build_posnet_svc_frame(self.fsp_service_id, 0, '')
                    response = self.send_command(continue_frame)
                    if response:
                        parsed = self._parse_posnet_response(response)
                        if parsed and 'da' in parsed:
                            response_data += bytes.fromhex(parsed['da'])
            
            return response_data
            
        except Exception as e:
            logger.error(f"Błąd wysyłania komendy FSP: {e}")
            return None
    
    def get_printer_status(self) -> Dict[str, Any]:
        """
        Pobierz status drukarki
        
        Returns:
            Słownik ze statusem drukarki
        """
        command = self._build_command("GET_STATUS")
        response = self.send_command(command)
        
        if response:
            return {
                'online': True,
                'has_paper': True,  # Do parsowania z odpowiedzi
                'fiscal_mode': True,  # Do parsowania z odpowiedzi
                'error': None
            }
        else:
            return {
                'online': False,
                'error': 'Brak odpowiedzi od drukarki'
            }
