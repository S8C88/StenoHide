# StenoHide — Engineering Report

## Overview

**Project:** StenoHide
**Version:** 1.0
**Author:** Sideways 8 Security Research
**Category:** Steganography / Covert Communication

StenoHide embeds and extracts arbitrary data in PNG/JPG images using Least Significant Bit (LSB) steganography with optional XOR encryption. No PIL/Pillow dependency — operates directly on raw byte data, making it lightweight and fast for command-line use during engagements.

---

## Tech Stack

### Language: Python 3.10+

Pure stdlib except for password-based XOR. No image processing libraries — we work directly on the PNG/JPG byte stream.

### Encryption: `hashlib` (stdlib) + XOR

Simple XOR cipher with SHA-256 key derivation. Not military-grade (no AES), but sufficient for CTF challenges, HTB boxes, and proof-of-concept stego exercises. The encryption exists to make casual inspection non-trivial, not to withstand forensic analysis.

### Binary packing: `struct` (stdlib)

Custom 8-byte header format: 4-byte magic (`STGH`) + 4-byte unsigned int for payload length. This lets the extractor verify it's reading valid stego data before attempting extraction.

---

## Architecture Decisions

### No PIL — why?

PIL/Pillow is the standard for image manipulation in Python, but it's heavy for our use case. StenoHide doesn't need to render, transform, or filter images — it only needs to read and write raw bytes. Working directly on the byte stream is faster, has zero dependencies, and avoids PIL's encoding quirks with different image modes.

### LSB approach vs. DCT

LSB steganography (modifying the least significant bit of each color channel) is the simplest form of image stego. It's detectable by statistical analysis (RS analysis, chi-square), but for CTF/educational use that's acceptable. DCT-based stego (like JSteg for JPEG) would be more covert but requires JPEG decompression/recompression, which needs PIL.

### PNG metadata approach

For clean extraction without corrupting the image, we embed data in PNG ancillary chunk metadata rather than modifying pixel data directly. This preserves visual integrity perfectly and survives re-saving by most image viewers.

### XOR encryption, not AES

AES would require pycryptodome or cryptography as a dependency. For a tool that's primarily educational/CTF-focused, XOR with SHA-256 key derivation is the right tradeoff between security and zero-dependency simplicity.

---

## File Structure

```
StenoHide/
├── stenohide.py         # LSB encode/decode
├── README.md            # Usage and examples
├── LICENSE              # MIT
├── requirements.txt     # (empty — no deps)
├── tests/
│   └── test_stenohide.py
└── docs/
    └── engineering-report.md
```

---

## Limitations

1. **Detectable by stegoanalysis tools** — LSB is the most well-studied stego technique. Tools like StegExpose, StegDetect, and manual RS analysis will flag LSB-modified images.
2. **Image must have enough capacity** — a 100x100 PNG has ~30KB of LSB capacity. Larger payloads need larger cover images.
3. **Re-saving JPEG destroys data** — JPEG's lossy compression corrupts LSB modifications. PNG or BMP only.
4. **Not deniable** — the STGH magic header in the metadata makes extraction trivial if someone looks.

---

## Future Work

- Add AES-256-GCM encryption option via pycryptodome.
- Implement DCT-based JPEG stego for better covertness.
- Add image quality metrics (PSNR, SSIM) to quantify detectability.
- Support for audio file stego (WAV LSB).
