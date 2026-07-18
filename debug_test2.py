#!/usr/bin/env python3
"""Debug the wrong password test"""
import sys, os, struct, zlib, tempfile

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("sh", os.path.join(os.path.dirname(__file__), "stenohide.py"))
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

# Test: wrong password
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, 'test.png')
    out = os.path.join(tmp, 'out.png')
    
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data)
    ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
    raw = b'\x00\x00\x00\xff'
    compressed = zlib.compress(raw)
    idat_crc = zlib.crc32(b'IDAT' + compressed)
    idat = struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)
    iend_crc = zlib.crc32(b'IEND')
    iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    with open(png, 'wb') as f:
        f.write(sig + ihdr + idat + iend)
    
    sh.hide_text(png, 'secret', out, 'correct_pw')
    result = sh.extract_text(out, 'wrong_pw')
    print(f'Result: {result}')
    print(f'Is None: {result is None}')
    
    # Also test no_data
    clean_out = os.path.join(tmp, 'clean.png')
    with open(clean_out, 'wb') as f:
        f.write(sig + ihdr + idat + iend)
    result2 = sh.extract_text(clean_out)
    print(f'No data result: {result2}')
    print(f'Is None: {result2 is None}')
    
    # Test that None != "secret" is True
    expected = "secret"
    print(f'None != expected: {result != expected}')
    print(f'None == expected: {result == expected}')
