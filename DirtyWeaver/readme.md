# 🕷️ DirtyWeaver (Advanced Crypto-Steganography Tool)

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A high-security steganography tool written in Python. It securely "weaves" arbitrary data (files, text) within digital carriers (PNG, BMP images and WAV, FLAC audio) using a modern, multi-layered crypto stack.

This project was designed with a clear **separation of concerns**:
1.  `crypto.py`: Manages *only* encryption, decryption, and key derivation.
2.  `steganography.py`: Manages *only* the low-level bit embedding and extraction.
3.  `main.py`: The orchestrator that handles the user interface, file I/O, and workflow.

---

*(Tip: A GIF or short video demo here is the best way to showcase your project.)*

`[Demo of the tool in action]`

---

## 🚀 Core Features

* **🔑 Secure KDF:** Uses **Argon2id** (the Password Hashing Competition winner) for key derivation, providing high resistance to GPU-based cracking.
* **🔒 Modern Crypto:** Implements AEAD (Authenticated Encryption) with **AES-GCM** or **ChaCha20-Poly1305**. Data is encrypted *before* it ever touches the carrier file.
* **🛡️ Plausible Deniability:** Supports a **Decoy Mode** with a separate password. This reveals innocuous "decoy" data, protecting the real payload under duress.
* **✨ Artifact-Free Embedding:** **Intelligently ignores Alpha (transparency) channels** in RGBA images. This prevents the visible artifacts and glitches that plague simpler LSB tools.
* **🎧 Audio Support:** Natively handles `.wav` and `.flac` files, automatically converting float-based samples to `int16` for safe LSB manipulation.
* **🎛️ Variable Depth (Bits-Per-Channel):** Allows the user to select 1, 2, or 3 bits per channel, balancing stealth against capacity.
* **⚙️ Smart Pre-processing:** Automatically handles:
    * Zipping directories into a single file.
    * `zlib` compression to maximize payload capacity.
    * Lossy-to-lossless conversion (JPEG → PNG) for safe embedding.
* **🖥️ Dual Interface:** Functions as both a powerful CLI tool (via `argparse`) and a user-friendly interactive menu for guided use.

---

## 🛠️ Tech Stack

* **Cryptography:** `cryptography`, `argon2-cffi`
* **Steganography:** `numpy` (for high-speed array manipulation), `Pillow (PIL)` (for images), `pysoundfile` (for audio)
* **UI & Utilities:** `tqdm` (for progress bars), `scipy` (for Chi-Squared analysis)

---

## 🏁 Getting Started

### 1. Requirements
* Python 3.9+
* All libraries listed in the `requirements.txt` file.

### 2. Installation

1.  Clone the repository (assuming your project is in the `DirtyWeaver` folder inside `DirtyLabs`):
    > `git clone https://github.com/Sperfect99/DirtyLabs.git`
    > `cd DirtyLabs/DirtyWeaver`

2.  (Recommended) Create and activate a virtual environment:
    > `python -m venv venv`
    > `source venv/bin/activate` (On Windows: `venv\Scripts\activate`)

3.  Install all required dependencies from the `requirements.txt` file:
    > `pip install -r requirements.txt`

---

## 🕹️ Full Usage Guide (CLI)

The tool can be run interactively by executing `python main.py` with no arguments, or by using the commands below.

### 1. Hide Data

**Command:**
> `python main.py hide [options]`

**Example:**
> `python main.py hide -i "photo.png" -o "secret.png" -f "my_document.zip" --bits 2 --decoy "This is just a decoy text."`

**Options:**
* **-i, --input** (Required): The carrier file (e.g., `photo.png`, `sound.wav`).
* **-o, --output** (Required): The destination output file (e.g., `hidden.png`).
* **-f, --file**: The secret file or folder you want to hide.
* **-t, --text**: Alternatively, the secret text you want to hide.
* **--decoy**: (Optional) An innocuous "decoy" message. You will be prompted for a separate decoy password.
* **--algo**: (Optional) `aes` or `chacha20`. Defaults to `aes`.
* **--bits**: (Optional) `1`, `2`, or `3`. LSBs per channel. `1`=max stealth, `3`=max capacity. Defaults to `1`.
* **--double**: (Optional) Flag to apply double encryption (prompts for a 2nd password).

### 2. Extract Data

**Command:**
> `python main.py extract [options]`

**Example:**
> `python main.py extract -i "secret.png" --bits 2`

**Options:**
* **-i, --input** (Required): The file containing the hidden data.
* **--bits** (Required): Must match the number of bits used during the hide process (`1`, `2`, or `3`).
* **--algo**: (Optional) `aes` or `chacha20`. Defaults to `aes`.
* **--double**: (Optional) Flag if the data was double-encrypted.


### 3. Utility Commands

#### Check Capacity
> `python main.py capacity -i "carrier.png" --bits 2`
> 
> Checks how many bytes can be hidden in a carrier file using the specified `bits` setting.

#### Analyze Carrier
> `python main.py analyze -i "suspicious.png"`
> 
> Runs a basic Chi-Squared LSB analysis on an image to check for statistical anomalies.

---

## 🧠 Design Decisions (How It Works)
This tool's architecture was designed to solve specific security and stability problems.

### 1. The Crypto Core (crypto.py)
Simply hashing a password (`SHA256(password)`) is not secure for key generation.

* **Why Argon2id?** It's a modern KDF (Key Derivation Function) that is "memory-hard." This means it's expensive to accelerate with GPUs, making brute-force attacks extremely slow and costly, unlike SHA256 which is designed for speed.
* **True Key Separation:** This is the most critical design choice. **One** user password generates **two** functionally distinct keys:
    1.  **Encryption Key:** (Argon2id + **Random Salt**) Used for the AES/ChaCha cipher. The unique salt is stored *with* the payload. This ensures that encrypting the same file twice produces two different ciphertexts (semantic security).
    2.  **Stego Seed:** (Argon2id + **Fixed Domain Salt**) This is a *deterministic* seed. The same password *always* produces the same seed. This seed is used *only* to initialize the PRNG (Pseudo-Random Number Generator) that determines *where* the bits are hidden.

    This separation is paramount: the `enc_key` protects the **data**, while the `stego_seed` protects the **location**.

### 2. The Stego Engine (steganography.py)
* **Why NumPy?** Loading a 4K image or a 5-minute audio file into a standard Python list would be a memory nightmare. `NumPy` loads the data as a flat, contiguous array, allowing LSB manipulation (via bitwise masks) to be performed nearly instantly with minimal memory overhead.
* **Why PRNG Shuffling?** Writing bits sequentially (from pixel 1 to pixel N) creates an obvious statistical footprint. Instead, this tool uses the `stego_seed` to `random.shuffle` a list of all available embedding indices. The payload is then "weaved" across the entire carrier in this pseudo-random, yet reproducible, pattern.
* **The Alpha Channel Problem:** A classic flaw in many LSB tools is modifying all channels, including Alpha (transparency). Modifying an alpha value (e.g., from 0 to 1) is almost always visible, creating a "ghosting" artifact. This code **explicitly identifies RGBA** carriers and builds an index list that **skips every 4th byte (the 'A')**, solving this problem completely.

---