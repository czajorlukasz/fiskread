import socket
import struct
from typing import Optional, Dict, Any, List
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Protokół POSNET
STX = b'\x02'
ETX = b'\x03'
TAB = b'\x09'

# Komendy FSP (zgodnie z PROTOCOL.txt + POSNET extensions)
CC_VERSION = 0x10
CC_ERR = 0x40
CC_GET_DIR = 0x41
CC_GET_FILE = 0x42
CC_BYE = 0x4A
CC_STAT = 0x4D  # Informacje o pliku (POSNET extension)


class FSPClient:
    def read_file_fsp(self, path: str, segment_size: int = 128) -> Optional[bytes]:
        """
        Pobierz plik segmentami, aż do końca (na wzór POSNET POP).
        Jeśli plik jest JSON, wyświetl go jako tekst.
        """
        import json
        position = 0
        result = b""
        while True:
            data = self.get_file(path, position)
            if not data or len(data) == 0:
                break
            result += data
            if len(data) < segment_size:
                break
            position += len(data)
        # Próbuj wyświetlić jako JSON
        try:
            text = result.decode('utf-8')
            obj = json.loads(text)
            print("--- Zawartość JSON ---")
            import pprint
            pprint.pprint(obj)
        except Exception:
            pass
        return result

    """Klient protokołu FSP zgodny ze specyfikacją FSP v2"""

    def __init__(self, ip_address: str, port: int = 2121, protocol: str = 'udp'):
        self.ip_address = ip_address
        self.port = port
        self.protocol = protocol.lower()
        self.timeout = 5  # Krótszy timeout - drukarka odpowiada szybko
        self.fsp_service_id = 1
        self.max_packet_size = 128
        # Stan sesji FSP
        # Zgodnie z oficjalną specyfikacją FSP:
        # - Klient zaczyna z key=0
        # - Serwer wybiera losowy klucz i wysyła w odpowiedzi
        # - Klient używa tego klucza w kolejnych zapytaniach
        self.key = 0  # Początkowy klucz (serwer wybierze nowy)
        self.sequence = 0  # Numer sekwencji (zaczyna od 0!)
        self.session_initialized = False
        logger.info(f"FSPClient utworzony z początkowym kluczem: 0x{self.key:04X}")
    
    def _init_session(self):
        """Inicjalizuj sesję FSP przez wysłanie CC_VERSION"""
        if self.session_initialized:
            return True
        
        try:
            logger.info("Inicjalizacja sesji FSP (CC_VERSION)...")
            fsp_packet = self._build_fsp_packet(CC_VERSION, 0, b'')
            response = self._send_fsp_through_svc(fsp_packet)
            
            if response:
                fsp_response = self._parse_fsp_packet(response)
                if fsp_response:
                    logger.info(f"✓ Sesja zainicjalizowana, key={self.key}")
                    self.session_initialized = True
                    return True
            
            logger.error("✗ Nie udało się zainicjalizować sesji")
            return False
            
        except Exception as e:
            logger.error(f"Błąd inicjalizacji sesji: {e}")
            return False
    
    def _calculate_posnet_checksum(self, data: bytes) -> str:
        """Suma kontrolna POSNET (XOR)"""
        checksum = 0
        for byte in data:
            checksum ^= byte
        checksum = (checksum ^ (checksum << 8)) & 0xFFFF
        return f"{checksum:04X}"
    
    def _build_posnet_svc_frame(self, service_id: int, flags: int, data_hex: str) -> bytes:
        """Buduj ramkę POSNET svc"""
        content = f"svc\tid{service_id}\tfl{flags}\tda{data_hex}\t".encode('ascii')
        checksum = self._calculate_posnet_checksum(content)
        frame = STX + content + f"#{checksum}".encode('ascii') + ETX
        return frame
    
    def _parse_posnet_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parsuj odpowiedź POSNET"""
        try:
            if response.startswith(STX):
                response = response[1:]
            if response.endswith(ETX):
                response = response[:-1]
            
            response_str = response.decode('ascii', errors='ignore')
            parts = response_str.split('\t')
            
            result = {'command': parts[0] if len(parts) > 0 else None}
            
            for part in parts[1:]:
                if part.startswith('id'):
                    result['id'] = int(part[2:])
                elif part.startswith('fl'):
                    result['fl'] = int(part[2:])
                elif part.startswith('da'):
                    result['da'] = part[2:]
                elif part.startswith('#'):
                    result['checksum'] = part[1:]
            
            return result
            
        except Exception as e:
            logger.error(f"Błąd parsowania odpowiedzi POSNET: {e}")
            return None
    
    def send_udp_command(self, data: bytes) -> Optional[bytes]:
        """Wyślij przez UDP i odbierz odpowiedź"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            sock.sendto(data, (self.ip_address, self.port))
            logger.info(f"Wysłano UDP: {data.hex()} do {self.ip_address}:{self.port}")
            
            response, addr = sock.recvfrom(65535)
            logger.info(f"Odebrano {len(response)} bajtów z {addr}")
            sock.close()
            
            return response
            
        except socket.timeout:
            logger.error("Timeout - brak odpowiedzi UDP")
            return None
        except Exception as e:
            logger.error(f"Błąd UDP: {e}")
            return None
    
    def _send_fsp_through_svc(self, fsp_packet: bytes) -> Optional[bytes]:
        """Wyślij pakiet FSP bezpośrednio przez UDP (czysty FSP, bez ramki svc)"""
        try:
            # Wysyłamy cały pakiet FSP bez segmentacji i bez ramki svc
            response = self.send_udp_command(fsp_packet)
            return response
        except Exception as e:
            logger.error(f"Błąd wysyłania czystego FSP: {e}")
            return None
    
    def _build_fsp_packet(self, command: int, position: int, data: bytes = b'') -> bytes:
        """
        Buduj pakiet FSP v2
        
        Header (12 bytes):
        - byte: command
        - byte: checksum  
        - word: key (big-endian)
        - word: sequence (big-endian)
        - word: data_length (big-endian)
        - long: position (big-endian)
        """
        data_length = len(data)
        
        # Nagłówek (bez checksumy)
        # Ensure fields fit into specified sizes (H = 0..65535)
        key_field = self.key & 0xFFFF
        seq_field = self.sequence & 0xFFFF
        data_length_field = data_length & 0xFFFF

        packet = struct.pack('>B', command)
        packet += b'\x00'  # Checksum placeholder
        packet += struct.pack('>H', key_field)
        packet += struct.pack('>H', seq_field)
        packet += struct.pack('>H', data_length_field)
        packet += struct.pack('>I', position & 0xFFFFFFFF)
        packet += data
        
        # Oblicz checksumę (client->server: initial = packet size)
        checksum_sum = len(packet)
        for byte in packet:
            checksum_sum += byte
        checksum = (checksum_sum + (checksum_sum >> 8)) & 0xFF
        
        # Wstaw checksumę
        packet = packet[0:1] + bytes([checksum]) + packet[2:]
        
        logger.debug(f"Pakiet FSP: cmd=0x{command:02X}, key={self.key}, seq={self.sequence}, pos={position}, len={data_length}")
        
        # Inkrementuj sequence dla następnego pakietu (wrap do 16 bitów)
        self.sequence = (self.sequence + 1) & 0xFFFF
        
        return packet
    
    def _parse_fsp_packet(self, packet: bytes) -> Optional[Dict[str, Any]]:
        """Parsuj pakiet FSP"""
        if len(packet) < 12:
            logger.error(f"Pakiet FSP za krótki: {len(packet)} bajtów")
            return None
        
        try:
            command = packet[0]
            checksum = packet[1]
            key = struct.unpack('>H', packet[2:4])[0]
            sequence = struct.unpack('>H', packet[4:6])[0]
            data_length = struct.unpack('>H', packet[6:8])[0]
            position = struct.unpack('>I', packet[8:12])[0]
            
            data = packet[12:12+data_length] if data_length > 0 else b''
            xtra_data = packet[12+data_length:] if len(packet) > 12+data_length else b''
            
            # Aktualizuj klucz sesji zgodnie ze specyfikacją FSP:
            # "Client's message to server contain a KEY value that is the same as the KEY 
            #  value of the previous message received from the server. KEY is chosen random by server."
            if key != 0:
                old_key = self.key
                self.key = key
                if old_key != key:
                    logger.info(f"Klucz sesji zaktualizowany: 0x{old_key:04X} -> 0x{key:04X}")
            
            logger.debug(f"Odpowiedź FSP: cmd=0x{command:02X}, key={key}, seq={sequence}, len={data_length}")
            
            return {
                'command': command,
                'key': key,
                'sequence': sequence,
                'data_length': data_length,
                'position': position,
                'data': data,
                'xtra_data': xtra_data
            }
            
        except Exception as e:
            logger.error(f"Błąd parsowania FSP: {e}")
            return None
    
    def list_directory(self, path: str, position: int = 0, preferred_size: int = 1024):
        """
        CC_GET_DIR (0x41) - Listuj katalog z paginacją i preferred_size (zgodnie z FSP v2)
        Args:
            path: Ścieżka (np. "0:EJ0/DOC")
            position: Pozycja w katalogu (offset)
            preferred_size: preferowany rozmiar bloku katalogu (domyślnie 1024)
        Returns:
            (entries, found_end) - lista wpisów i czy znaleziono RDTYPE_END
        """
        try:
            if not self._init_session():
                return [], False
            logger.info(f"FSP GET_DIR: {path} pos={position} preferred_size={preferred_size}")
            path_bytes = path.encode('utf-8') + b'\x00'
            xtra_data = struct.pack('>H', preferred_size)
            fsp_packet = self._build_fsp_packet(CC_GET_DIR, position, path_bytes + xtra_data)
            response = self._send_fsp_through_svc(fsp_packet)
            if not response:
                return [], False
            fsp_response = self._parse_fsp_packet(response)
            if not fsp_response:
                return [], False
            if fsp_response['command'] == CC_ERR:
                error_msg = fsp_response['data'].decode('utf-8', errors='ignore').strip('\x00')
                logger.error(f"FSP ERROR: {error_msg}")
                return [], False
            entries, found_end = self._parse_directory_listing_with_end(fsp_response['data'])
            logger.info(f"Znaleziono {len(entries)} wpisów (found_end={found_end})")
            return entries, found_end
        except Exception as e:
            logger.error(f"Błąd GET_DIR: {e}")
            return [], False

    def _parse_directory_listing_with_end(self, data: bytes):
        """
        Parsuj directory listing i wykryj RDTYPE_END (0x00)
        Zwraca: (entries, found_end)
        """
        entries = []
        offset = 0
        found_end = False
        try:
            while offset + 9 < len(data):
                timestamp = struct.unpack('>I', data[offset:offset+4])[0]
                size = struct.unpack('>I', data[offset+4:offset+8])[0]
                entry_type = data[offset+8]
                name_offset = offset + 9
                name_end = name_offset
                while name_end < len(data) and data[name_end] != 0:
                    name_end += 1
                name = data[name_offset:name_end].decode('utf-8', errors='replace')
                entry_len = ((name_end - offset) + 1 + 3) & ~3
                offset = offset + 9 + (name_end - name_offset) + 1
                offset = ((offset + 3) // 4) * 4
                if entry_type == 0x00:  # RDTYPE_END
                    found_end = True
                    break
                type_name = {0x01: 'FILE', 0x02: 'DIR'}.get(entry_type, 'UNKNOWN')
                if not name or type_name == 'UNKNOWN':
                    continue
                entries.append({
                    'name': name,
                    'type': type_name,
                    'size': size,
                    'timestamp': timestamp,
                    'date': datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else None,
                    'is_dir': (type_name == 'DIR' or entry_type == 2)
                })
            return entries, found_end
        except Exception as e:
            logger.error(f"Błąd parsowania directory listing: {e}")
            return entries, found_end
    
    def _parse_directory_listing(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Parsuj directory listing
        
        RDIRENT format:
        - long time (4 bytes, big-endian)
        - long size (4 bytes, big-endian)
        - byte type
        - ASCIIZ name
        - padding to 4-byte boundary
        """
        entries = []
        offset = 0
        try:
            while offset + 9 < len(data):
                timestamp = struct.unpack('>I', data[offset:offset+4])[0]
                size = struct.unpack('>I', data[offset+4:offset+8])[0]
                entry_type = data[offset+8]
                name_offset = offset + 9
                # Szukaj końca ASCIIZ
                name_end = name_offset
                while name_end < len(data) and data[name_end] != 0:
                    name_end += 1
                name = data[name_offset:name_end].decode('utf-8', errors='replace')
                # Padding do 4 bajtów
                entry_len = ((name_end - offset) + 1 + 3) & ~3
                offset = offset + 9 + (name_end - name_offset) + 1
                offset = ((offset + 3) // 4) * 4
                type_name = {0x01: 'FILE', 0x02: 'DIR'}.get(entry_type, 'UNKNOWN')
                # Filtruj wpisy z pustą nazwą lub typem UNKNOWN
                if not name or type_name == 'UNKNOWN':
                    continue
                entries.append({
                    'name': name,
                    'type': type_name,
                    'size': size,
                    'timestamp': timestamp,
                    'date': datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else None,
                    'is_dir': (type_name == 'DIR' or entry_type == 2)
                })
            return entries
        except Exception as e:
            logger.error(f"Błąd parsowania directory listing: {e}")
            return []
            
            entries.append({
                'name': name,
                'type': type_name,
                'size': size,
                'timestamp': timestamp,
                'date': datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else None
            })
        
        return entries
    
    def get_file(self, path: str, position: int = 0) -> Optional[bytes]:
        """
        CC_GET_FILE (0x42) - Pobierz plik
        
        Args:
            path: Ścieżka pliku (np. "0:EJ0/DOC/0/00/00/000000009.BIN")
            position: Offset w pliku
            
        Returns:
            Dane pliku lub None
        """
        try:
            # Inicjalizuj sesję jeśli potrzeba
            if not self._init_session():
                return None
            
            logger.info(f"FSP GET_FILE: {path} offset={position}")
            
            path_bytes = path.encode('utf-8') + b'\x00'
            fsp_packet = self._build_fsp_packet(CC_GET_FILE, position, path_bytes)
            
            response = self._send_fsp_through_svc(fsp_packet)
            if not response:
                return None
            
            fsp_response = self._parse_fsp_packet(response)
            if not fsp_response:
                return None
            
            if fsp_response['command'] == CC_ERR:
                error_msg = fsp_response['data'].decode('utf-8', errors='ignore').strip('\x00')
                logger.error(f"FSP ERROR: {error_msg}")
                return None
            
            logger.info(f"Pobrano {len(fsp_response['data'])} bajtów")
            return fsp_response['data']
            
        except Exception as e:
            logger.error(f"Błąd GET_FILE: {e}")
            return None
    
    def stat_file(self, path: str) -> Optional[Dict[str, Any]]:
        """
        CC_STAT (0x4D) - Pobierz informacje o pliku/katalogu
        
        Args:
            path: Ścieżka (np. "EJ0/MEDIUM.DAT")
            
        Returns:
            Słownik z informacjami o pliku lub None
        """
        try:
            logger.info(f"FSP STAT: {path}")
            
            path_bytes = path.encode('utf-8') + b'\x00'
            fsp_packet = self._build_fsp_packet(CC_STAT, 0, path_bytes)
            
            response = self._send_fsp_through_svc(fsp_packet)
            if not response:
                return None
            
            fsp_response = self._parse_fsp_packet(response)
            if not fsp_response:
                return None
            
            if fsp_response['command'] == CC_ERR:
                error_msg = fsp_response['data'].decode('utf-8', errors='ignore').strip('\x00')
                logger.error(f"FSP ERROR: {error_msg}")
                return None
            
            # Parsuj odpowiedź STAT (podobnie do RDIRENT)
            data = fsp_response['data']
            if len(data) >= 12:
                timestamp = struct.unpack('>I', data[0:4])[0]
                size = struct.unpack('>I', data[4:8])[0]
                file_type = data[8]
                
                return {
                    'timestamp': timestamp,
                    'size': size,
                    'type': {0x01: 'FILE', 0x02: 'DIR'}.get(file_type, 'UNKNOWN'),
                    'date': datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else None
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Błąd STAT: {e}")
            return None
    
    def close(self):
        """Zakończ sesję FSP (CC_BYE)"""
        try:
            fsp_packet = self._build_fsp_packet(CC_BYE, 0, b'')
            self._send_fsp_through_svc(fsp_packet)
            logger.info("Sesja FSP zakończona")
        except:
            pass
