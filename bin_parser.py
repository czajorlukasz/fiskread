"""Simple BIN parser following DKO POT-I-DEV-38 (subset).

Provides parse_records(data) -> yields (rec_type, rec_size, rec_data, parsed)
and helpers to parse common record types (0x44 header, 0x41 footer, 0x0A line, 0x6D SHA, 0x20/0x74 signatures).
"""
from typing import Generator, Tuple, Optional, Dict, Any

BIN_RECORD_NAMES = {
    0x0A: 'Linia',
    0x41: 'Stopka',
    0x42: 'Raport dobowy (biletowy)',
    0x44: 'Nagłówek dokumentu',
    0x6D: 'Skrót SHA',
    0x20: 'Podpis RSA512',
    0x74: 'Podpis RSA2048',
    0x61: 'Pozycja / Sprzedaż',
    0x63: 'Pole danych (string?)',
    0x64: 'Kwoty (BCD?)',
    0x6A: 'Pole binarne',
    0x76: 'Szczegóły pozycji',
    0x73: 'Meta / flags',
    0x59: '0x59',
    0xC0: 'Duży blok (JPK/PKCS?)',
    0x20: 'Podpis RSA512',
    0xB8: '0xB8',
}

import struct
from datetime import datetime, timedelta
import re


def _asciiz(b: bytes) -> str:
    raw = b.split(b'\x00', 1)[0]
    # prefer cp1250 (Polish devices), fallback to utf-8
    try:
        return raw.decode('cp1250')
    except Exception:
        return raw.decode('utf-8', errors='replace')


def parse_records(data: bytes) -> Generator[Tuple[int, int, bytes, Optional[Dict[str,Any]]], None, None]:
    """Yield (rec_type, rec_size, rec_data, parsed) for each record in data.
    rec_size includes 6-byte header.
    """
    offset = 0
    idx = 0
    while offset + 6 <= len(data):
        reserved = int.from_bytes(data[offset:offset+2], 'big')
        rec_type = int.from_bytes(data[offset+2:offset+4], 'big')
        rec_size = int.from_bytes(data[offset+4:offset+6], 'big')
        if rec_size < 6:
            # malformed
            break
        rec_data = data[offset+6: offset+rec_size]
        parsed = None
        try:
            parsed = parse_record(rec_type, rec_data)
        except Exception:
            parsed = None
        yield rec_type, rec_size, rec_data, parsed
        offset += rec_size
        idx += 1
        if rec_size == 0:
            break


def parse_record(rec_type: int, data: bytes) -> Optional[Dict[str,Any]]:
    if rec_type == 0x44:
        return parse_header_0x44(data)
    if rec_type == 0x41:
        return parse_footer_0x41(data)
    if rec_type == 0x0A:
        return parse_line_0x0A(data)
    if rec_type == 0x54:
        return parse_text_0x54(data)
    if rec_type == 0x6D:
        return parse_sha_0x6D(data)
    if rec_type == 0x61:
        return parse_sale_0x61(data)
    if rec_type == 0x63:
        return parse_packaging_0x63(data)
    if rec_type == 0x64:
        return parse_values_0x64(data)
    if rec_type == 0x6A:
        return parse_payment_0x6A(data)
    if rec_type == 0x73:
        return parse_sum_currency_0x73(data)
    if rec_type == 0x76:
        return parse_vat_summary_0x76(data)
    if rec_type in (0x20, 0x74):
        return parse_signature(rec_type, data)
    return parse_unknown(data)


def extract_printable_strings(data: bytes, min_len: int = 4):
    """Return list of printable (utf-8 or ascii) substrings found in data."""
    out = []
    try:
        s = data.decode('utf-8', errors='replace')
    except Exception:
        s = ''.join((chr(b) if 32 <= b < 127 else '\ufffd') for b in data)
    # find runs of printable chars
    for m in re.finditer(r'[\w\-\./:,\\() \u0080-\uFFFF]{%d,}' % min_len, s):
        txt = m.group(0).strip('\x00')
        if txt:
            out.append(txt)
    return out


def parse_unknown(data: bytes) -> Dict[str, Any]:
    """Generic fallback parser — exposes hex prefix and printable substrings."""
    return {
        'hex_prefix': data[:48].hex(),
        'strings': extract_printable_strings(data, min_len=4)
    }


def parse_header_0x44(data: bytes) -> Dict[str,Any]:
    # As spec: 1 byte doc type, 4 unsigned long date, 4 unsigned long doc number,
    # 1 byte mode, 10 char NIP, 1 char prefix, followed by others
    out = {}
    off = 0
    if len(data) < 1:
        return out
    out['doc_type'] = data[off]
    off += 1
    if len(data) >= off + 4:
        out['timestamp'] = int.from_bytes(data[off:off+4], 'big')
        out['timestamp_iso'] = ts_from_fsp(out['timestamp'])
        off += 4
    if len(data) >= off + 4:
        out['doc_number'] = int.from_bytes(data[off:off+4], 'big')
        off += 4
    if len(data) >= off + 1:
        out['mode'] = data[off]
        off += 1
    # NIP 10 chars
    if len(data) >= off + 10:
        out['nip'] = _asciiz(data[off:off+10])
        off += 10
    # 1 char prefix
    if len(data) >= off + 1:
        out['prefix'] = _asciiz(data[off:off+1])
        off += 1
    # remaining: flags / optional fields - keep raw
    if len(data) > off:
        out['rest'] = data[off:]
    return out


def parse_footer_0x41(data: bytes) -> Dict[str,Any]:
    out = {}
    off = 0
    # 1 byte doc type
    if len(data) >= off + 1:
        out['doc_type'] = data[off]
        off += 1
    # 1 byte mode
    if len(data) >= off + 1:
        out['mode'] = data[off]
        off += 1
    # 1 byte status
    if len(data) >= off + 1:
        out['status'] = data[off]
        off += 1
    # 4 bytes doc number
    if len(data) >= off + 4:
        out['doc_number'] = int.from_bytes(data[off:off+4], 'big')
        off += 4
    # 4 bytes timestamp
    if len(data) >= off + 4:
        out['timestamp'] = int.from_bytes(data[off:off+4], 'big')
        out['timestamp_iso'] = ts_from_fsp(out['timestamp'])
        off += 4
    # 14 char unique number
    if len(data) >= off + 14:
        out['unique_number'] = _asciiz(data[off:off+14])
        off += 14
    # 8 char kasa number
    if len(data) >= off + 8:
        out['kasa_number'] = _asciiz(data[off:off+8])
        off += 8
    # 32 char cashier name
    if len(data) >= off + 32:
        out['cashier'] = _asciiz(data[off:off+32])
        off += 32
    # 30 char buyer NIP
    if len(data) >= off + 30:
        out['buyer_nip'] = _asciiz(data[off:off+30])
        off += 30
    # remaining
    if len(data) > off:
        out['rest'] = data[off:]
    return out


def parse_line_0x0A(data: bytes) -> Dict[str,Any]:
    # pascal string: first byte = length, rest = text (may contain formatting)
    if not data:
        return {'text': ''}
    ln = data[0]
    raw = data[1:1+ln]
    # prefer cp1250 (Polish devices), fallback to utf-8
    try:
        text = raw.decode('cp1250')
    except Exception:
        text = raw.decode('utf-8', errors='replace')
    return {'text': text}


def parse_sha_0x6D(data: bytes) -> Dict[str,Any]:
    # spec: 32 bytes SHA256 (or SHA) - store hex
    return {'sha_hex': data[:32].hex()}


def parse_signature(rec_type: int, data: bytes) -> Dict[str,Any]:
    # rec_type 0x20 -> RSA512 (64 bytes), 0x74 -> RSA2048 (256 bytes)
    return {'sig_len': len(data), 'sig_hex_prefix': data[:16].hex()}


def ts_from_fsp(seconds_since_2000: int) -> str:
    '''Convert seconds since 2000-01-01 to ISO8601.'''
    base = datetime(2000, 1, 1)
    try:
        dt = base + timedelta(seconds=seconds_since_2000)
        return dt.isoformat()
    except Exception:
        return str(seconds_since_2000)


def bcd_to_int(b: bytes) -> int:
    '''Convert BCD bytes to integer (no sign).'''
    s = ''
    for byte in b:
        hi = (byte >> 4) & 0xF
        lo = byte & 0xF
        s += f"{hi}{lo}"
    # strip leading zeros
    return int(s.lstrip('0') or '0')


def bcd_to_decimal(b: bytes, precision: int) -> float:
    i = bcd_to_int(b)
    if precision == 0:
        return float(i)
    return i / (10 ** precision)


def bcd6_to_decimal(b: bytes, precision: int = 2) -> float:
    """Convenience for 6-byte BCD (tBcdVal)."""
    if len(b) >= 6:
        return bcd_to_decimal(b[:6], precision)
    return bcd_to_decimal(b, precision)


def parse_sale_0x61(data: bytes) -> Dict[str,Any]:
    '''Attempt to parse a sale record (0x61) per DKO subset.'''
    out = {}
    off = 0
    try:
        # 80 char name
        if len(data) >= off + 80:
            out['name'] = data[off:off+80].split(b'\x00',1)[0].decode('cp1250',errors='replace')
        else:
            out['name'] = data[off:off+80].decode('cp1250',errors='replace')
        off += 80
        # 1 byte VAT symbol
        if len(data) >= off + 1:
            out['vat_symbol'] = chr(data[off]) if 0x20 <= data[off] < 0x7F else f"{data[off]:02X}"
        off += 1
        # 6 BCD price
        if len(data) >= off + 6:
            out['price'] = bcd_to_decimal(data[off:off+6], 2)  # assume 2 decimals
        off += 6
        # 6 BCD total
        if len(data) >= off + 6:
            out['total'] = bcd_to_decimal(data[off:off+6], 2)
        off += 6
        # 6 BCD qty
        if len(data) >= off + 6:
            out['quantity'] = bcd_to_decimal(data[off:off+6], 2)
        off += 6
        # 1 byte precision
        if len(data) >= off + 1:
            out['precision'] = data[off]
        off += 1
        # 4 char unit
        if len(data) >= off + 4:
            out['unit'] = data[off:off+4].split(b'\x00',1)[0].decode('cp1250',errors='replace')
        off += 4
        # 50 char description
        if len(data) >= off + 50:
            out['desc'] = data[off:off+50].split(b'\x00',1)[0].decode('cp1250',errors='replace')
        else:
            out['desc'] = data[off:].split(b'\x00',1)[0].decode('cp1250',errors='replace')
    except Exception:
        pass
    return out


def parse_text_0x54(data: bytes) -> Dict[str,Any]:
    out = {}
    if len(data) >= 4:
        out['id'] = int.from_bytes(data[0:4], 'big')
        text = data[4:]
        if text:
            # pascal-like? try to strip trailing zeros
            out['text'] = text.split(b'\x00',1)[0].decode('cp1250', errors='replace')
    else:
        out['id'] = int.from_bytes(data, 'big') if data else 0
    return out


def parse_packaging_0x63(data: bytes) -> Dict[str,Any]:
    out = {}
    off = 0
    # 40 char name
    if len(data) >= off + 40:
        out['name'] = data[off:off+40].split(b'\x00',1)[0].decode('cp1250',errors='replace')
    off += 40
    # 6 BCD value
    if len(data) >= off + 6:
        out['value'] = bcd6_to_decimal(data[off:off+6], 2)
    off += 6
    # 6 BCD qty (precision follows)
    qty_raw = None
    if len(data) >= off + 6:
        qty_raw = data[off:off+6]
    off += 6
    # 1 byte precision
    precision = 2
    if len(data) >= off + 1:
        precision = data[off]
        out['precision'] = precision
    off += 1
    # compute qty using precision
    if qty_raw is not None:
        out['qty'] = bcd_to_decimal(qty_raw, precision)
    # 6 BCD total (use standard 2 decimals)
    if len(data) >= off + 6:
        out['total'] = bcd6_to_decimal(data[off:off+6], 2)
    off += 6
    # sign/type
    if len(data) >= off + 2:
        out['sign'] = data[off]
        out['kind'] = data[off+1]
    return out


def parse_values_0x64(data: bytes) -> Dict[str,Any]:
    out = {}
    off = 0
    if len(data) >= off + 1:
        out['section_type'] = data[off]
        off += 1
    # next 6 bytes value
    if len(data) >= off + 6:
        out['value'] = bcd6_to_decimal(data[off:off+6], 2)
        off += 6
    if len(data) >= off + 3:
        out['currency'] = data[off:off+3].decode('ascii', errors='replace')
        off += 3
    if len(data) >= off + 1:
        out['vat_id'] = data[off]
    return out


def parse_payment_0x6A(data: bytes) -> Dict[str,Any]:
    out = {}
    off = 0
    if len(data) >= off + 1:
        out['cash_flag'] = data[off]
        off += 1
    if len(data) >= off + 1:
        out['type'] = data[off]
        off += 1
    if len(data) >= off + 6:
        out['amount'] = bcd6_to_decimal(data[off:off+6], 2)
        off += 6
    if len(data) >= off + 25:
        out['name'] = data[off:off+25].split(b'\x00',1)[0].decode('cp1250', errors='replace')
        off += 25
    if len(data) >= off + 3:
        out['currency'] = data[off:off+3].decode('ascii', errors='replace')
    return out


def parse_sum_currency_0x73(data: bytes) -> Dict[str,Any]:
    out = {}
    off = 0
    vals = []
    # read as many 6-byte BCDs as possible
    while len(data) >= off + 6:
        vals.append(bcd6_to_decimal(data[off:off+6], 2))
        off += 6
    out['values'] = vals
    if len(data) >= off + 3:
        out['currency'] = data[off:off+3].decode('ascii', errors='replace')
        off += 3
    if len(data) > off:
        out['rest'] = data[off:]
    return out


def parse_vat_summary_0x76(data: bytes) -> Dict[str,Any]:
    out = {}
    off = 0
    rates = []
    # first 14 unsigned shorts if present
    if len(data) >= off + 14 * 2:
        for i in range(14):
            rates.append(int.from_bytes(data[off:off+2], 'big'))
            off += 2
        out['rates'] = rates
    # then read sequences of 6-byte BCDs for brutto and tax (try to read pairs)
    nums = []
    while len(data) >= off + 6:
        nums.append(bcd6_to_decimal(data[off:off+6], 2))
        off += 6
    out['numbers'] = nums
    if len(data) >= off + 3:
        out['currency'] = data[off:off+3].decode('ascii', errors='replace')
    return out


def assemble_document(data: bytes) -> Dict[str, Any]:
    """Assemble parsed records into a document-level dictionary.

    Returns keys: header, items, packaging, values, payments, vat_summary, totals, footer, signatures, sha, raw_records
    """
    doc: Dict[str, Any] = {
        'header': None,
        'items': [],
        'packaging': [],
        'values': [],
        'payments': [],
        'vat_summary': None,
        'totals': None,
        'footer': None,
        'signatures': [],
        'sha': None,
        'raw_records': []
    }
    current_item = None
    for rec_type, rec_size, rec_data, parsed in parse_records(data):
        doc['raw_records'].append({'type': rec_type, 'size': rec_size})
        if rec_type == 0x44:
            doc['header'] = parsed
        elif rec_type == 0x0A:
            # line of text
            text = parsed.get('text') if parsed else rec_data.decode('cp1250', errors='replace')
            # lines may be both header/footer; collect as general lines
            doc.setdefault('lines', []).append(text)
        elif rec_type == 0x61:
            current_item = parsed or {'name': rec_data.hex()}
            current_item.setdefault('extras', [])
            doc['items'].append(current_item)
        elif rec_type == 0x63:
            parsed_p = parsed or parse_packaging_0x63(rec_data)
            # associate with current item if exists
            if current_item is not None:
                current_item.setdefault('packaging', []).append(parsed_p)
            else:
                doc['packaging'].append(parsed_p)
        elif rec_type == 0x64:
            parsed_v = parsed or parse_values_0x64(rec_data)
            # may be per-item or document-level; attach to current_item if exists
            if current_item is not None:
                current_item.setdefault('values', []).append(parsed_v)
            else:
                doc['values'].append(parsed_v)
        elif rec_type == 0x6A:
            parsed_pay = parsed or parse_payment_0x6A(rec_data)
            doc['payments'].append(parsed_pay)
        elif rec_type == 0x76:
            doc['vat_summary'] = parsed or parse_vat_summary_0x76(rec_data)
        elif rec_type == 0x73:
            doc['totals'] = parsed or parse_sum_currency_0x73(rec_data)
        elif rec_type == 0x41:
            doc['footer'] = parsed
        elif rec_type == 0x6D:
            doc['sha'] = parsed
        elif rec_type in (0x20, 0x74):
            doc['signatures'].append(parsed)
        else:
            # keep unknowns in a list for later analysis
            doc.setdefault('unknowns', []).append({'type': rec_type, 'parsed': parsed})

    return doc
