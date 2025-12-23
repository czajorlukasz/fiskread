"""Scan data/ for BIN files and extract packaging records (0x63).

Usage: python scripts/find_packaging.py [data-root]
Prints CSV with: file, doc_number, timestamp_iso, item_name, pack_name, qty, value, total
"""
import sys
import os
import csv
import unicodedata
# ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Usage: python scripts/find_packaging.py [data-root] [--all]
ROOT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else os.path.join(os.getcwd(), 'data')
SHOW_ALL = '--all' in sys.argv
AGGREGATE = '--aggregate' in sys.argv
CSV_OUT = '--csv' in sys.argv

from bin_parser import parse_records, BIN_RECORD_NAMES, parse_packaging_0x63, ts_from_fsp


def _norm_name(s: str):
    if not s:
        return s
    try:
        s2 = unicodedata.normalize('NFKC', s)
    except Exception:
        s2 = s
    return s2.strip()


def scan_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    last_item_name = None
    doc_number = ''
    timestamp_iso = ''
    results = []
    for rec_type, rec_size, rec_data, parsed in parse_records(data):
        if rec_type == 0x44 and parsed:
            doc_number = parsed.get('doc_number')
            timestamp_iso = parsed.get('timestamp_iso')
        elif rec_type == 0x61:
            # item name
            if parsed and parsed.get('name'):
                last_item_name = parsed.get('name')
            else:
                last_item_name = None
        elif rec_type == 0x63:
            p = None
            try:
                p = parsed or parse_packaging_0x63(rec_data)
            except Exception:
                p = {'error': 'parse_failed', 'hex': rec_data.hex()[:64]}
            results.append((path, doc_number, timestamp_iso, last_item_name, p))
        elif rec_type == 0x0A:
            # textual line - detect packaging mentions like 'kaucja' or 'OPAKOWANIA'
            text = parsed.get('text') if parsed else rec_data.decode('cp1250', errors='replace')
            if not text:
                continue
            txt_l = text.lower()
            if 'kaucja' in txt_l or 'opakow' in txt_l:
                # try to extract pattern: name ... qty xprice total (comma decimal)
                import re
                m = re.search(r"(?P<name>.+?)\s+(?P<qty>-?\d+)\s*[x×]\s*(?P<price>[\d,]+)\s*(?P<total>-?[\d,]+)", text)
                if m:
                    name = m.group('name').strip()
                    qty = m.group('qty')
                    price = m.group('price').replace(',', '.')
                    total = m.group('total').replace(',', '.')
                    p = {'name': name, 'qty': float(qty), 'value': float(price), 'total': float(total), 'source': 'line'}
                else:
                    p = {'text': text, 'source': 'line'}
                results.append((path, doc_number, timestamp_iso, last_item_name, p))
        # reset last_item_name when encountering separators? keep simple: keep last item
    return results


def walk_and_collect(root):
    out = []
    for dirpath, dirs, files in os.walk(root):
        for fn in files:
            if fn.upper().endswith('.BIN'):
                path = os.path.join(dirpath, fn)
                # scan_file returns tuples: (path, doc_number, timestamp_iso, last_item_name, p)
                rows = scan_file(path)
                # determine location and printer from relative path under root
                rel = os.path.relpath(path, root)
                parts = rel.split(os.sep)
                location = parts[0] if len(parts) > 0 else ''
                printer = parts[1] if len(parts) > 1 else ''
                for row in rows:
                    out.append(tuple(list(row) + [printer, location]))
    return out


def main():
    rows = walk_and_collect(ROOT)
    # debug: show number of rows collected
    # print(f"DEBUG rows collected: {len(rows)}")
    writer = csv.writer(sys.stdout, lineterminator='\n')
    def _print_table(headers, rows_data):
        # rows_data: list of lists (strings)
        # compute col widths
        cols = len(headers)
        widths = [len(h) for h in headers]
        for r in rows_data:
            for i in range(cols):
                v = '' if i >= len(r) or r[i] is None else str(r[i])
                widths[i] = max(widths[i], len(v))
        # build format: left-align for first col, right-align for numeric-looking cols
        is_num = [False] * cols
        for i in range(cols):
            # heuristics: header name suggests numeric, or all values parse as float
            if headers[i].lower() in ('qty', 'value', 'total', 'sum_total', 'rows', 'returns', 'issued'):
                is_num[i] = True
            else:
                # check values
                allnum = True
                for r in rows_data:
                    try:
                        if i >= len(r):
                            continue
                        float(str(r[i]).replace(',', '.'))
                    except Exception:
                        allnum = False
                        break
                is_num[i] = allnum
        # header
        hdr_parts = []
        for i, h in enumerate(headers):
            if is_num[i]:
                hdr_parts.append(h.rjust(widths[i]))
            else:
                hdr_parts.append(h.ljust(widths[i]))
        print('  '.join(hdr_parts))
        # separator
        sep_parts = [('-' * w) for w in widths]
        print('  '.join(sep_parts))
        # rows
        for r in rows_data:
            parts = []
            for i in range(cols):
                v = '' if i >= len(r) or r[i] is None else str(r[i])
                if is_num[i]:
                    parts.append(v.rjust(widths[i]))
                else:
                    parts.append(v.ljust(widths[i]))
            print('  '.join(parts))

    def _short_path(s: str, maxlen: int = 60) -> str:
        if not s:
            return s
        if len(s) <= maxlen:
            return s
        # keep head and tail
        head = s[:maxlen//2 - 3]
        tail = s[-(maxlen//2 - 3):]
        return head + '...' + tail
    if AGGREGATE:
        # simpler aggregation by location+printer: rows, returns, issued, sum_total
        agg = {}
        for path, doc_number, timestamp_iso, item_name, p, printer, location in rows:
            if not isinstance(p, dict):
                continue
            name = _norm_name(p.get('name') or p.get('pack_name') or '')
            if not name:
                continue
            total = float(p.get('total') or 0)
            key = (location, printer, name)
            rec = agg.setdefault(key, {'rows': 0, 'returns': 0, 'issued': 0, 'sum_total': 0.0})
            rec['rows'] += 1
            if total < 0:
                rec['returns'] += 1
            else:
                rec['issued'] += 1
            rec['sum_total'] += total
        # prepare rows grouped by location then printer
        headers = ['location', 'printer', 'pack_name', 'rows', 'returns', 'issued', 'sum_total']
        rows_out = []
        for (location, printer, name), rec in sorted(agg.items()):
            rows_out.append([location, printer, name, rec['rows'], rec['returns'], rec['issued'], f"{rec['sum_total']:.2f}"])
        if CSV_OUT:
            writer.writerow(headers)
            for r in rows_out:
                writer.writerow(r)
        else:
            _print_table(headers, rows_out)
        return

    headers = ['location', 'printer', 'file', 'doc_number', 'timestamp', 'pack_name', 'qty', 'value', 'total']
    rows_out = []
    for path, doc_number, timestamp_iso, item_name, p, printer, location in rows:
        if not isinstance(p, dict):
            continue
        name = _norm_name(p.get('name') or p.get('pack_name') or '')
        qty = p.get('qty')
        value = p.get('value')
        total = p.get('total')
        # by default only show packaging records (non-empty pack name)
        if not SHOW_ALL and not name:
            continue
        # show only filename (basename) to keep terminal table compact
        rows_out.append([location, printer, os.path.basename(path), doc_number, timestamp_iso, name, qty, value, total])
    if CSV_OUT:
        writer.writerow(headers)
        for r in rows_out:
            writer.writerow(r)
    else:
        # shorten file paths for display (file is 3rd column now)
        rows_disp = []
        for r in rows_out:
            r2 = list(r)
            if len(r2) >= 3 and r2[2]:
                r2[2] = _short_path(str(r2[2]), maxlen=40)
            rows_disp.append(r2)
        _print_table(headers, rows_disp)


if __name__ == '__main__':
    main()
