"""Inspect local BIN file and print parsed records.
Usage: python inspect_bin.py path/to/00000001.BIN
"""
import sys
import os
# ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from bin_parser import parse_records, BIN_RECORD_NAMES, assemble_document


def main():
    if len(sys.argv) < 2:
        print('Usage: inspect_bin.py <path-to-bin>')
        return
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()
    for idx, (rec_type, rec_size, rec_data, parsed) in enumerate(parse_records(data)):
        name = BIN_RECORD_NAMES.get(rec_type, f'0x{rec_type:02X}')
        print(f"[{idx}] type=0x{rec_type:02X} ({name}), size={rec_size}")
        if parsed:
            # human-friendly formatting
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    print(f"   {k}: {v}")
            else:
                print('   parsed:', parsed)
        else:
            # print first 64 bytes hex
            print('   raw:', rec_data[:64].hex(), ('...' if len(rec_data)>64 else ''))
    # assembled document summary
    print('\n--- Document summary ---')
    doc = assemble_document(data)
    if doc.get('header'):
        print('Header:')
        for k, v in doc['header'].items():
            print(f"  {k}: {v}")
    print('\nItems:')
    for it in doc.get('items', []):
        name = it.get('name')
        qty = it.get('quantity')
        price = it.get('price')
        total = it.get('total')
        vat = it.get('vat_symbol', '')
        try:
            print(f" - {name}    {qty} x{price:.2f} {total:.2f}{vat}")
        except Exception:
            print(' -', name, qty, price, total, vat)
        if it.get('packaging'):
            for p in it['packaging']:
                print(f"   pack: {p.get('name')} {p.get('qty')}x{p.get('value'):.2f} {p.get('total'):.2f}")
    if doc.get('packaging'):
        print('\nDocument packaging:')
        for p in doc['packaging']:
            print(' -', p)
    print('\nPayments:')
    for pay in doc.get('payments', []):
        nm = pay.get('name') or ''
        amt = pay.get('amount')
        cur = pay.get('currency','')
        try:
            print(f" - {nm} {amt:.2f} {cur}")
        except Exception:
            print(' -', nm, amt, cur)
    print('\nTotals:')
    print(doc.get('totals'))
    print('\nFooter:')
    if doc.get('footer'):
        for k, v in doc['footer'].items():
            print(f"  {k}: {v}")

if __name__ == '__main__':
    main()
