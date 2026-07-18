#!/usr/bin/env python3
"""Debug script for StenoHide"""
import sys, os, struct, zlib, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("sh", os.path.join(os.path.dirname(__file__), "stenohide.py"))
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

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

with tempfile.TemporaryDirectory() as tmp:
    png_path = os.path.join(tmp, 'test.png')
    out_path = os.path.join(tmp, 'out.png')
    with open(png_path, 'wb') as f:
        f.write(sig + ihdr + idat + iend)
    print(f'PNG size: {os.path.getsize(png_path)} bytes')
    
    sh.hide_text(png_path, 'hello stego', out_path)
    print(f'Output size: {os.path.getsize(out_path)} bytes')
    
    # Check the output file structure
    with open(out_path, 'rb') as f:
        d = f.read()
    iend_pos = d.rfind(b'IEND')
    print(f'IEND at byte: {iend_pos}')
    print(f'Trailer after IEND: {d[iend_pos:iend_pos+50]}')
    
    result = sh.extract_text(out_path)
    print(f'Extracted: {result}')
    print(f'Match: {result == "hello stego"}')
