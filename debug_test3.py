#!/usr/bin/env python3
"""Identify which test is failing"""
import sys, os, struct, zlib, tempfile, importlib

sys.path.insert(0, os.path.dirname(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

spec = importlib.util.spec_from_file_location("sh", os.path.join(PROJECT_DIR, "stenohide.py"))
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

# Test each function individually
tests = {}

def make_png(path):
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
    with open(path, 'wb') as f:
        f.write(sig + ihdr + idat + iend)

# Test 1: Basic roundtrip
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, 't.png')
    out = os.path.join(tmp, 'o.png')
    make_png(png)
    sh.hide_text(png, 'hello', out)
    result = sh.extract_text(out)
    print(f'Test 1 (basic): {result == "hello"}')

# Test 2: Password
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, 't.png')
    out = os.path.join(tmp, 'o.png')
    make_png(png)
    sh.hide_text(png, 'secret', out, 'pw')
    result = sh.extract_text(out, 'pw')
    print(f'Test 2 (pw): {result == "secret"}')

# Test 3: Wrong password
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, 't.png')
    out = os.path.join(tmp, 'o.png')
    make_png(png)
    sh.hide_text(png, 'secret', out, 'correct')
    result = sh.extract_text(out, 'wrong')
    ok = result is None or result != 'secret'
    print(f'Test 3 (wrong pw): {ok}')

# Test 4: No data
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, 't.png')
    make_png(png)
    result = sh.extract_text(png)
    print(f'Test 4 (no data): {result is None}')

# Test 5: Empty msg
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, 't.png')
    out = os.path.join(tmp, 'o.png')
    make_png(png)
    sh.hide_text(png, '', out)
    result = sh.extract_text(out)
    print(f'Test 5 (empty): {result == ""}')

# Test 6: Long msg
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, 't.png')
    out = os.path.join(tmp, 'o.png')
    make_png(png)
    sh.hide_text(png, 'A' * 500, out)
    result = sh.extract_text(out)
    print(f'Test 6 (long 500): {result == "A"*500}')

# Test 7: Unicode
with tempfile.TemporaryDirectory() as tmp:
    png = os.path.join(tmp, 't.png')
    out = os.path.join(tmp, 'o.png')
    make_png(png)
    sh.hide_text(png, 'héllo', out)
    result = sh.extract_text(out)
    print(f'Test 7 (unicode): {result == "héllo"}')

# Test 8: LSB
with tempfile.TemporaryDirectory() as tmp:
    bmp_path = os.path.join(tmp, 't.bmp')
    out_path = os.path.join(tmp, 'o.bmp')
    width, height = 2, 2
    row_size = (width * 3 + 3) & ~3
    pixel_data = b'\x00' * (row_size * height)
    file_size = 54 + len(pixel_data)
    bmp = bytearray()
    bmp += b'BM'
    bmp += struct.pack('<I', file_size)
    bmp += struct.pack('<HH', 0, 0)
    bmp += struct.pack('<I', 54)
    bmp += struct.pack('<I', 40)
    bmp += struct.pack('<i', width)
    bmp += struct.pack('<i', -height)
    bmp += struct.pack('<HH', 1, 24)
    bmp += struct.pack('<I', 0)
    bmp += struct.pack('<I', len(pixel_data))
    bmp += struct.pack('<i', 2835)
    bmp += struct.pack('<i', 2835)
    bmp += struct.pack('<I', 0)
    bmp += struct.pack('<I', 0)
    bmp += pixel_data
    with open(bmp_path, 'wb') as f:
        f.write(bmp)
    ok = sh.lsb_encode_pixels(bmp_path, 'lsb test', out_path)
    extracted = sh.lsb_decode_pixels(out_path)
    print(f'Test 8 (LSB encode): {ok}')
    print(f'Test 8 (LSB decode): {extracted == "lsb test"}')
