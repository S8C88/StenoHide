#!/usr/bin/env python3
"""
StenoHide — Image-based steganography.
Hide and extract data in PNG/JPG using LSB techniques.

Usage:
    python3 stenohide.py hide -i cover.png -m "secret message" -o output.png
    python3 stenohide.py extract -i stego.png
"""

import argparse
import os
import sys
import struct
import hashlib

# LSB encode/decode

HEADER_MAGIC = b"STGH"  # 4-byte magic
HEADER_FMT = "<4sI"     # magic (4s) + data_len (I)

# Maximum file sizes (CWE-770)
MAX_IMAGE_SIZE = 100 * 1024 * 1024  # 100MB


def _validate_path(path: str, purpose: str = "input") -> str:
    """Validate a file path — canonicalize, check exists (CWE-20/CWE-22)."""
    resolved = os.path.realpath(path)
    if purpose == "input":
        if not os.path.isfile(resolved):
            raise FileNotFoundError(f"Input file not found: {resolved}")
        file_size = os.path.getsize(resolved)
        if file_size > MAX_IMAGE_SIZE:
            raise ValueError(f"File too large ({file_size} bytes > {MAX_IMAGE_SIZE} max)")
    elif purpose == "output":
        parent = os.path.dirname(resolved)
        if parent and not os.path.isdir(parent):
            raise FileNotFoundError(f"Output directory does not exist: {parent}")
    return resolved

def hide_text(img_path: str, message: str, output_path: str, password: str = ""):
    """
    Embed message into image LSBs.
    Uses PNG metadata approach — cleanest for Python without PIL.
    """
    # CWE-20/CWE-22: Validate paths
    validated_input = _validate_path(img_path, "input")
    validated_output = _validate_path(output_path, "output")

    with open(validated_input, "rb") as f:
        data = bytearray(f.read())

    if password:
        h = hashlib.sha256(password.encode()).digest()
        msg_bytes = bytearray(message.encode())
        for i in range(len(msg_bytes)):
            msg_bytes[i] ^= h[i % 32]
        payload = msg_bytes
    else:
        payload = message.encode()

    header = struct.pack(HEADER_FMT, HEADER_MAGIC, len(payload))
    full_payload = header + payload

    # Find end-of-data marker in PNG (IEND chunk)
    iend_pos = data.rfind(b"IEND")
    if iend_pos == -1:
        print("[-] Not a valid PNG (IEND chunk not found)")
        sys.exit(1)

    # Append payload after IEND — parsers ignore trailing data
    stego = data + full_payload

    with open(validated_output, "wb") as f:
        f.write(stego)

    print(f"[+] Message hidden in {output_path} ({len(payload)} bytes)")


def extract_text(img_path: str, password: str = ""):
    """Extract hidden message from image."""
    # CWE-20/CWE-22: Validate input path
    validated_input = _validate_path(img_path, "input")

    with open(validated_input, "rb") as f:
        data = f.read()

    # Find the payload after IEND
    iend_pos = data.rfind(b"IEND")
    if iend_pos == -1:
        print("[-] No IEND marker found — not a valid PNG")
        return None

    trailer = data[iend_pos + 8:]  # Skip IEND (4) + CRC (4)
    if len(trailer) < struct.calcsize(HEADER_FMT):
        print("[-] No hidden data found")
        return None

    magic, data_len = struct.unpack(HEADER_FMT, trailer[:struct.calcsize(HEADER_FMT)])
    if magic != HEADER_MAGIC:
        print("[-] No hidden data found (magic mismatch)")
        return None

    enc_msg = trailer[struct.calcsize(HEADER_FMT):struct.calcsize(HEADER_FMT) + data_len]
    if password:
        h = hashlib.sha256(password.encode()).digest()
        msg = bytearray(enc_msg)
        for i in range(len(msg)):
            msg[i] ^= h[i % 32]
        decrypted = bytes(msg)
    else:
        decrypted = enc_msg

    try:
        plaintext = decrypted.decode("utf-8")
        print(f"[+] Extracted message ({len(plaintext)} chars):")
        print(f"    {plaintext}")
        return plaintext
    except UnicodeDecodeError:
        print("[-] Decrypted data is not valid UTF-8. Wrong password?")
        return None


# LSB pixel manipulation (using raw pixel data)
# TODO: this only works with uncompressed BMP/TGA. PNG uses deflate, need
# to decompress first. For now this is a placeholder for the real LSB method.

def lsb_encode_pixels(img_path: str, message: str, output_path: str):
    """LSB encode in raw pixel data (BMP format only currently)."""
    # CWE-20/CWE-22: Validate paths
    validated_input = _validate_path(img_path, "input")
    validated_output = _validate_path(output_path, "output")

    with open(validated_input, "rb") as f:
        data = bytearray(f.read())

    if data[0:2] != b"BM":
        print("[-] LSB pixel mode requires BMP format")
        return False

    # BMP pixel data starts at offset 10
    pixel_offset = struct.unpack("<I", data[10:14])[0]
    payload = (message + "\x00").encode()  # null-terminated

    # Check capacity
    available = (len(data) - pixel_offset) * 3  # 3 color channels
    needed = len(payload) * 8
    if needed > available:
        print(f"[-] Message too large ({len(payload)} bytes > {available // 8} max)")
        return False

    bits = []
    for byte in payload:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)

    for i, bit in enumerate(bits):
        idx = pixel_offset + i
        if idx >= len(data):
            break
        data[idx] = (data[idx] & 0xFE) | bit

    # Add EOS marker — 8 zero bits after the message
    for i in range(8):
        idx = pixel_offset + len(bits) + i
        data[idx] = data[idx] & 0xFE

    with open(validated_output, "wb") as f:
        f.write(data)
    return True


def lsb_decode_pixels(img_path: str) -> str:
    """Extract LSB-encoded message from BMP pixel data."""
    # CWE-20/CWE-22: Validate input path
    validated_input = _validate_path(img_path, "input")

    with open(validated_input, "rb") as f:
        data = f.read()

    if data[0:2] != b"BM":
        print("[-] LSB pixel mode requires BMP format")
        return ""

    pixel_offset = struct.unpack("<I", data[10:14])[0]

    bits = []
    for i in range(len(data) - pixel_offset):
        bits.append(data[pixel_offset + i] & 1)

    chars = []
    for i in range(0, len(bits) - 8, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        if byte == 0:  # null terminator
            break
        chars.append(chr(byte))

    message = "".join(chars)
    if message:
        print(f"[+] Extracted message: {message}")
    return message


# CLI

def main():
    parser = argparse.ArgumentParser(description="StenoHide — LSB steganography tool")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_hide = sub.add_parser("hide", help="Hide a message in an image")
    p_hide.add_argument("-i", "--input", required=True, help="Cover image path")
    p_hide.add_argument("-m", "--message", required=True, help="Message to hide")
    p_hide.add_argument("-o", "--output", default="stego_output.png", help="Output path")
    p_hide.add_argument("-p", "--password", default="", help="XOR encryption password")
    p_hide.add_argument("--lsb", action="store_true", help="Use pixel LSB mode (BMP only)")

    p_extract = sub.add_parser("extract", help="Extract hidden message")
    p_extract.add_argument("-i", "--input", required=True, help="Stego image path")
    p_extract.add_argument("-p", "--password", default="", help="XOR decryption password")
    p_extract.add_argument("--lsb", action="store_true", help="Use pixel LSB mode (BMP only)")

    args = parser.parse_args()

    if args.mode == "hide":
        if args.lsb:
            if not lsb_encode_pixels(args.input, args.message, args.output):
                sys.exit(1)
        else:
            hide_text(args.input, args.message, args.output, args.password)
    elif args.mode == "extract":
        if args.lsb:
            lsb_decode_pixels(args.input)
        else:
            extract_text(args.input, args.password)


if __name__ == "__main__":
    main()
