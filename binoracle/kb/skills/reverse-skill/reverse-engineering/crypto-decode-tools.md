# Encryption / Decoding Tools Cheat Sheet

> Encryption/decoding/hashing data is frequently encountered in reverse engineering and CTF challenges. This document lists the most practical tools by scenario.

---

## Auto-Identify + Decrypt (When You Don't Know What Encryption Was Used)

| Tool | Stars | Purpose | Link |
|------|-------|---------|------|
| **Ciphey** | 18k+ | AI auto-identify and decrypt (supports over 50 encoding/encryption/hashing) | https://github.com/Ciphey/Ciphey |
| **CyberChef** | 29k+ | Online/offline decoding Swiss Army Knife (drag-and-drop operations) | https://github.com/gchq/CyberChef |
| **dcode.fr** | — | Online 900+ password/encoding/math tools | https://www.dcode.fr/ |

### Ciphey Usage

```bash
pip install ciphey
# Auto-detect and decrypt
ciphey -t "ciphertext"
# From file read
ciphey -f encrypted.txt
```

Ciphey supports: Base64/32/16, Caesar, Vigenere, XOR, AES (weak keys), Morse, Binary, Hex, URL encoding, HTML entities, hash recognition, etc.

### CyberChef Usage

```text
Online version: https://gchq.github.io/CyberChef/
Offline version: Download the HTML file from GitHub Release and open directly

Common Recipes:
- From Base64 → Decode Base64
- XOR → XOR decryption (try key brute force)
- AES Decrypt → AES decryption
- Magic → Auto-detect encoding type
```

---

## Hash Identification and Cracking

| Tool | Purpose | Link |
|------|---------|------|
| **hashID** | Identify hash types (MD5/SHA/bcrypt, etc.) | https://github.com/psypanda/hashID |
| **hash-identifier** | Same as above, Python version | https://github.com/blackploit/hash-identifier |
| **haiti** | Modern hash identification tool (more accurate) | `gem install haiti` |
| **Hashcat** | GPU hash cracking | https://hashcat.net/ |
| **John the Ripper** | CPU hash cracking | https://www.openwall.com/john/ |
| **hashes.com** | Online hash query (rainbow tables) | https://hashes.com/ |

```bash
# Identify hash type
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
# Output: [+] MD5

# haiti (more accurate)
haiti '5f4dcc3b5aa765d61d8327deb882cf99'

# Hashcat cracking
hashcat -m 0 hash.txt rockyou.txt  # MD5
hashcat -m 1000 hash.txt rockyou.txt  # NTLM
```

---

## RSA Attacks

| Tool | Purpose | Link |
|------|---------|------|
| **RsaCtfTool** | RSA auto-attack (20+ attack methods) | https://github.com/Ganapati/RsaCtfTool |
| **SageMath** | Mathematical computation (large number factorization/elliptic curves) | https://www.sagemath.org/ |
| **factordb.com** | Online large number factorization query | http://factordb.com/ |
| **yafu** | Local large number factorization | https://github.com/bbuhrow/yafu |

```bash
# RsaCtfTool auto-attack
python RsaCtfTool.py --publickey pub.pem --private
python RsaCtfTool.py --publickey pub.pem --uncipherfile cipher.txt

# Supported attacks:
# Wiener, Boneh-Durfee, Fermat, Pollard p-1, Williams p+1
# Common modulus, Small q, Hastads, Noveltyprimes, etc.
```

---

## XOR Analysis

| Tool | Purpose | Link |
|------|---------|------|
| **xortool** | XOR key length guessing + known plaintext attack | https://github.com/hellman/xortool |
| **CyberChef XOR** | Visualize XOR operations | Built-in in CyberChef |

```bash
# Guess XOR key length
xortool encrypted_file
# Decrypt with guessed key length
xortool -l 4 -c 00 encrypted_file

# Known plaintext attack (known part of the plaintext)
xortool-xor -f encrypted -s "known_plaintext"
```

---

## Classical Ciphers

| Cipher Type | Tool | Description |
|-------------|------|-------------|
| Caesar      | CyberChef / dcode.fr | Brute force 25 offset shifts |
| Vigenere    | dcode.fr / Ciphey | Needs to guess key length |
| Substitution| quipqiup.com | Frequency analysis auto-solves |
| Enigma      | dcode.fr | Online simulator |
| Rail Fence  | dcode.fr / CyberChef | Fence cipher |
| Playfair    | dcode.fr | Needs key |
| Morse       | CyberChef | Dots and dashes to text |
| Bacon       | dcode.fr | Binary steganography |
| ROT13/47    | CyberChef / `tr` | Simple substitution |

---

## Encoding Recognition and Conversion

| Encoding | Identification Feature | Decoding Method |
|----------|------------------------|-----------------|
| Base64   | Ends with `=` or `==`, character set A-Za-z0-9+/ | `base64 -d` / CyberChef |
| Base32   | Uppercase + 2-7, ends with `=` | CyberChef |
| Base58   | No 0/O/I/l, commonly used for short identifier encoding | CyberChef |
| Hex      | Only 0-9a-f, even length | `xxd -r -p` / CyberChef |
| URL encoding | `%XX` format | `urldecode` / CyberChef |
| HTML entities | `&#XX;` or `&amp;` format | CyberChef |
| Unicode escape | `\uXXXX` format | Python `decode('unicode_escape')` |
| JWT      | `xxxxx.yyyyy.zzzzz` (three segments of Base64URL) | jwt.io / CyberChef |
| Brainfuck | Only `><+-.,[]` eight characters | Online interpreter |
| Ook!     | Only `Ook.` `Ook!` `Ook?` | Online interpreter |

---

## Encryption Identification in Reversing

### Through Constant Recognition Algorithms

| Constant/Feature | Algorithm |
|------------------|-----------|
| `0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476` | MD5 |
| `0x6A09E667, 0xBB67AE85, 0x3C6EF372` | SHA-256 |
| `0x63, 0x7C, 0x77, 0x7B` (S-Box starts) | AES |
| `0x243F6A88` (π in hexadecimal) | Blowfish |
| `0xB7E15163, 0x9E3779B9` | RC5/RC6/TEA |
| `0x61707865` ("expa") | ChaCha20/Salsa20 |
| `0xC6EF3720` | XTEA |

### Through Behavioral Recognition

| Behavioral Feature | Possible Algorithms |
|--------------------|---------------------|
| 256-byte lookup table + swap operation | RC4 |
| 16-byte block + multiple rounds of substitution | AES |
| Feistel structure (left-right swap) | DES/Blowfish/TEA |
| Large number multiplication/exponentiation | RSA |
| Elliptic curve point operations | ECDSA/ECDH |
| Fixed 64-round loop | TEA/XTEA |
| 32 rounds + delta constant | XTEA |

---

## Automated Password Analysis

| Tool | Purpose | Link |
|------|---------|------|
| **FeatherDuster** | Automated password analysis framework | https://github.com/nccgroup/featherduster |
| **PkCrack** | ZIP known plaintext attack | https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html |
| **bkcrack** | Modern version of ZIP known plaintext attack | https://github.com/kimci86/bkcrack |
| **z3** | SMT solver (constraint solving) | https://github.com/Z3Prover/z3 |
| **angr** | Symbolic execution (automatically solve inputs) | https://angr.io/ |

---

## Quick Decision Tree

```text
When you get a piece of unknown data:

1. Look at the length and character set:
   - Only hex characters → Possible hex encoding or hash
   - Ends with = → Base64
   - Three segments separated by dots → JWT
   - 32/40/64-character hex → Hash (MD5/SHA1/SHA256)

2. Use Ciphey to automatically try:
   ciphey -t "data"

3. If Ciphey fails → Use CyberChef Magic mode

4. If it's a hash → hashID identifies type → Hashcat/John cracks

5. If it's RSA → RsaCtfTool auto-attacks

6. If it's XOR → xortool analyzes key

7. If it's traditional ZIP encryption → Prefer using `bkcrack` known plaintext attack, don't do password brute-force without evidence

8. If it's custom encryption → IDA/Ghidra reverse algorithms → Write a decryption script
```

## Online Resources

| Resource | Link | Purpose |
|----------|------|---------|
| CyberChef | https://gchq.github.io/CyberChef/ | Universal encoder/decoder |
| dcode.fr | https://www.dcode.fr/ | 900+ password tools |
| quipqiup | https://quipqiup.com/ | Auto-solve substitution ciphers |
| factordb | http://factordb.com/ | RSA big integer factorization |
| jwt.io | https://jwt.io/ | JWT decoding/validation |
| hashes.com | https://hashes.com/ | Hash lookup |
| crackstation | https://crackstation.net/ | Online hash cracking |