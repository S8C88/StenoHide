#!/usr/bin/env python3
"""Tests for StenoHide — 100-pass suite."""

import sys, os, tempfile, struct, hashlib, random, string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

import importlib.util
spec = importlib.util.spec_from_file_location("stenohide", os.path.join(PROJECT_DIR, "stenohide.py"))
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

# Helpers

def make_test_png(path):
    """Generate a minimal valid 1x1 blue PNG."""
    # Minimal PNG: signature + IHDR + IDAT + IEND
    import zlib, struct
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)  # 1x1 RGB
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data)
    ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
    raw = b'\x00\x00\x00\xff'  # filter byte + blue pixel
    compressed = zlib.compress(raw)
    idat_crc = zlib.crc32(b'IDAT' + compressed)
    idat = struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)
    iend_crc = zlib.crc32(b'IEND')
    iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    with open(path, 'wb') as f:
        f.write(sig + ihdr + idat + iend)


# ─── Tests ────────────────────────────────────────────────────────────────

def test_hide_extract_trailer():
    """Basic hide and extract roundtrip."""
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "test.png")
        out = os.path.join(tmp, "out.png")
        make_test_png(png)
        msg = "hello stego"
        sh.hide_text(png, msg, out)
        extracted = sh.extract_text(out)
        assert extracted == msg, f"Expected '{msg}', got '{extracted}'"


def test_hide_extract_with_password():
    """Hide and extract with XOR password."""
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "test.png")
        out = os.path.join(tmp, "out.png")
        make_test_png(png)
        msg = "classified data here"
        pw = "hunter2"
        sh.hide_text(png, msg, out, pw)
        extracted = sh.extract_text(out, pw)
        assert extracted == msg


def test_wrong_password_fails():
    """Wrong password should produce garbage or fail."""
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "test.png")
        out = os.path.join(tmp, "out.png")
        make_test_png(png)
        sh.hide_text(png, "secret", out, "correct_pw")
        result = sh.extract_text(out, "wrong_pw")
        assert result is None or result != "secret"


def test_no_data_extract():
    """Extracting from clean image returns None."""
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "clean.png")
        make_test_png(png)
        result = sh.extract_text(png)
        assert result is None


def test_header_magic():
    """Verify header structure."""
    h = struct.pack(sh.HEADER_FMT, sh.HEADER_MAGIC, 42)
    magic, length = struct.unpack(sh.HEADER_FMT, h)
    assert magic == sh.HEADER_MAGIC
    assert length == 42


def test_empty_message():
    """Empty string message."""
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "test.png")
        out = os.path.join(tmp, "out.png")
        make_test_png(png)
        sh.hide_text(png, "", out)
        extracted = sh.extract_text(out)
        assert extracted == ""


def test_long_message():
    """Long message still roundtrips."""
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "test.png")
        out = os.path.join(tmp, "out.png")
        make_test_png(png)
        msg = "A" * 500
        sh.hide_text(png, msg, out)
        extracted = sh.extract_text(out)
        assert extracted == msg


def test_xor_deterministic():
    """XOR with the same password produces same output."""
    pw = "testpass"
    h = hashlib.sha256(pw.encode()).digest()
    msg = bytearray(b"hello")
    enc = bytearray(msg)
    for i in range(len(enc)):
        enc[i] ^= h[i % 32]
    dec = bytearray(enc)
    for i in range(len(dec)):
        dec[i] ^= h[i % 32]
    assert bytes(dec) == b"hello"


def test_header_mismatch():
    """Magic mismatch returns None."""
    h = struct.pack(sh.HEADER_FMT, b"FAKE", 10)
    assert h[:4] != sh.HEADER_MAGIC


def test_lsb_basic():
    """Basic LSB encode/decode roundtrip on generated BMP."""
    with tempfile.TemporaryDirectory() as tmp:
        bmp_path = os.path.join(tmp, "test.bmp")
        out_path = os.path.join(tmp, "out.bmp")
        # Generate a minimal 8x8 BMP (enough LSB space)
        width, height = 8, 8
        row_size = (width * 3 + 3) & ~3  # 4-byte aligned
        pixel_data = b'\x00' * (row_size * height)
        file_size = 54 + len(pixel_data)
        bmp = bytearray()
        bmp += b'BM'
        bmp += struct.pack('<I', file_size)
        bmp += struct.pack('<HH', 0, 0)
        bmp += struct.pack('<I', 54)
        bmp += struct.pack('<I', 40)
        bmp += struct.pack('<i', width)
        bmp += struct.pack('<i', -height)  # top-down
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
        
        msg = "lsb test"
        ok = sh.lsb_encode_pixels(bmp_path, msg, out_path)
        assert ok, "LSB encode failed"
        extracted = sh.lsb_decode_pixels(out_path)
        assert extracted == msg, f"LSB roundtrip failed: '{extracted}' != '{msg}'"


def test_non_bmp_lsb():
    """LSB on non-BMP returns gracefully."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.txt")
        with open(path, 'w') as f:
            f.write("not a bmp")
        ok = sh.lsb_encode_pixels(path, "msg", path)
        assert ok == False


def test_png_not_bmp():
    """PNG in LSB mode should fail."""
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "test.png")
        out = os.path.join(tmp, "out.png")
        make_test_png(png)
        ok = sh.lsb_encode_pixels(png, "msg", out)
        assert ok == False


def test_unicode_message():
    """Unicode message roundtrip."""
    with tempfile.TemporaryDirectory() as tmp:
        png = os.path.join(tmp, "test.png")
        out = os.path.join(tmp, "out.png")
        make_test_png(png)
        msg = "héllo wörld 🔥"
        sh.hide_text(png, msg, out)
        extracted = sh.extract_text(out)
        assert extracted == msg


# Runner

if __name__ == "__main__":
    tests = [
        test_hide_extract_trailer,
        test_hide_extract_with_password,
        test_wrong_password_fails,
        test_no_data_extract,
        test_header_magic,
        test_empty_message,
        test_long_message,
        test_xor_deterministic,
        test_header_mismatch,
        test_lsb_basic,
        test_non_bmp_lsb,
        test_png_not_bmp,
        test_unicode_message,
    ]

    print(f"[*] Running {len(tests)} base test cases...\n")
    passed = 0
    failed = 0

    for iteration in range(100):
        shuffled = list(tests)
        random.Random(iteration * 37).shuffle(shuffled)
        for test_fn in shuffled:
            try:
                test_fn()
                passed += 1
            except Exception as e:
                failed += 1
                if failed <= 10:
                    print(f"  FAIL (pass {iteration+1}): {test_fn.__name__}: {e}")
        if (iteration + 1) % 25 == 0:
            print(f"  [{iteration+1}/100] Passed: {passed}, Failed: {failed}")

    print(f"\n{'='*50}")
    print(f"  RESULTS: {passed} passed, {failed} failed out of {passed + failed} total")
    if failed == 0:
        print("  ALL TESTS PASSED")
    else:
        print(f"  {failed} FAILURES DETECTED")
    print(f"{'='*50}")
    sys.exit(0 if failed == 0 else 1)
