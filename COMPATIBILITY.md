# CyberChef compatibility

This inventory is pinned to CyberChef 11.3.0 at commit
`c56dd23358e948aff9f3f98913818e544227da13`.

- Upstream operations: 502
- Implemented operation names: 502
- Missing operation names: 0
- Name coverage: 100.0%

“Implemented” means that a callable operation is registered. It does not claim
bit-for-bit parity for every option combination. The pytest suite contains the
ported upstream vectors currently verified by PyChef.

Some callable operations currently provide dependency-free format subsets or
compatibility fallbacks. The most important parity work still open within the
registered set is MD6/Snefru/Streebog/Whirlpool, Twofish and advanced GOST,
general QR decoding, JPEG/TIFF codecs, complete historical-machine parity,
full JavaScript/Jq/Jsonata and YARA grammars, general-purpose OCR, complete
instruction decoding, and interoperable OpenPGP packet support.

| Operation | Status |
|---|---|
| A1Z26 Cipher Decode | implemented |
| A1Z26 Cipher Encode | implemented |
| ADD | implemented |
| AES Decrypt | implemented |
| AES Encrypt | implemented |
| AES Key Unwrap | implemented |
| AES Key Wrap | implemented |
| AMF Decode | implemented |
| AMF Encode | implemented |
| AND | implemented |
| Add Text To Image | implemented |
| Add line numbers | implemented |
| Adler-32 Checksum | implemented |
| Affine Cipher Decode | implemented |
| Affine Cipher Encode | implemented |
| Alternating Caps | implemented |
| Analyse UUID | implemented |
| Analyse hash | implemented |
| Argon2 | implemented |
| Argon2 compare | implemented |
| Ascon Decrypt | implemented |
| Ascon Encrypt | implemented |
| Ascon Hash | implemented |
| Ascon MAC | implemented |
| Atbash Cipher | implemented |
| Automated Validation Test Op | implemented |
| Avro to JSON | implemented |
| BLAKE2b | implemented |
| BLAKE2s | implemented |
| BLAKE3 | implemented |
| BSON deserialise | implemented |
| BSON serialise | implemented |
| Bacon Cipher Decode | implemented |
| Bacon Cipher Encode | implemented |
| Bcrypt | implemented |
| Bcrypt compare | implemented |
| Bcrypt parse | implemented |
| Bifid Cipher Decode | implemented |
| Bifid Cipher Encode | implemented |
| Bit shift left | implemented |
| Bit shift right | implemented |
| Blowfish Decrypt | implemented |
| Blowfish Encrypt | implemented |
| Blur Image | implemented |
| Bombe | implemented |
| Bzip2 Compress | implemented |
| Bzip2 Decompress | implemented |
| CBOR Decode | implemented |
| CBOR Encode | implemented |
| CMAC | implemented |
| CRC Checksum | implemented |
| CSS Beautify | implemented |
| CSS Minify | implemented |
| CSS selector | implemented |
| CSV to JSON | implemented |
| CTPH | implemented |
| Caesar Box Cipher | implemented |
| Caret/M-decode | implemented |
| Cartesian Product | implemented |
| Cetacean Cipher Decode | implemented |
| Cetacean Cipher Encode | implemented |
| ChaCha | implemented |
| Change IP format | implemented |
| Chi Square | implemented |
| CipherSaber2 Decrypt | implemented |
| CipherSaber2 Encrypt | implemented |
| Citrix CTX1 Decode | implemented |
| Citrix CTX1 Encode | implemented |
| Colossus | implemented |
| Comment | implemented |
| Compare CTPH hashes | implemented |
| Compare SSDEEP hashes | implemented |
| Conditional Jump | implemented |
| Contain Image | implemented |
| Convert Image Format | implemented |
| Convert Leet Speak | implemented |
| Convert area | implemented |
| Convert co-ordinate format | implemented |
| Convert data units | implemented |
| Convert distance | implemented |
| Convert mass | implemented |
| Convert speed | implemented |
| Convert to NATO alphabet | implemented |
| Count occurrences | implemented |
| Cover Image | implemented |
| Crop Image | implemented |
| DES Decrypt | implemented |
| DES Encrypt | implemented |
| DNS over HTTPS | implemented |
| DateTime Delta | implemented |
| Dechunk HTTP response | implemented |
| Decode NetBIOS Name | implemented |
| Decode text | implemented |
| Defang IP Addresses | implemented |
| Defang URL | implemented |
| Derive EVP key | implemented |
| Derive HKDF key | implemented |
| Derive PBKDF2 key | implemented |
| Detect File Type | implemented |
| Diff | implemented |
| Disassemble ARM | implemented |
| Disassemble x86 | implemented |
| Dither Image | implemented |
| Divide | implemented |
| Drop bytes | implemented |
| Drop nth bytes | implemented |
| ECDSA Sign | implemented |
| ECDSA Signature Conversion | implemented |
| ECDSA Verify | implemented |
| ELF Info | implemented |
| Encode NetBIOS Name | implemented |
| Encode text | implemented |
| Enigma | implemented |
| Entropy | implemented |
| Escape Smart Characters | implemented |
| Escape Unicode Characters | implemented |
| Escape string | implemented |
| Expand alphabet range | implemented |
| Extended GCD | implemented |
| Extract Audio Metadata | implemented |
| Extract EXIF | implemented |
| Extract Files | implemented |
| Extract ID3 | implemented |
| Extract IP addresses | implemented |
| Extract LSB | implemented |
| Extract MAC addresses | implemented |
| Extract RGBA | implemented |
| Extract URLs | implemented |
| Extract dates | implemented |
| Extract domains | implemented |
| Extract email addresses | implemented |
| Extract file paths | implemented |
| Extract hashes | implemented |
| Fang URL | implemented |
| Fernet Decrypt | implemented |
| Fernet Encrypt | implemented |
| File Tree | implemented |
| Filter | implemented |
| Find / Replace | implemented |
| Flask Session Decode | implemented |
| Flask Session Sign | implemented |
| Flask Session Verify | implemented |
| Fletcher-16 Checksum | implemented |
| Fletcher-32 Checksum | implemented |
| Fletcher-64 Checksum | implemented |
| Fletcher-8 Checksum | implemented |
| Flip Image | implemented |
| Fork | implemented |
| Format MAC addresses | implemented |
| Frequency distribution | implemented |
| From BCD | implemented |
| From Base | implemented |
| From Base32 | implemented |
| From Base45 | implemented |
| From Base58 | implemented |
| From Base62 | implemented |
| From Base64 | implemented |
| From Base85 | implemented |
| From Base92 | implemented |
| From Bech32 | implemented |
| From Binary | implemented |
| From Braille | implemented |
| From COBS | implemented |
| From Case Insensitive Regex | implemented |
| From Charcode | implemented |
| From Decimal | implemented |
| From Float | implemented |
| From HTML Entity | implemented |
| From Hex | implemented |
| From Hex Content | implemented |
| From Hexdump | implemented |
| From MessagePack | implemented |
| From Modhex | implemented |
| From Morse Code | implemented |
| From Octal | implemented |
| From Punycode | implemented |
| From Quoted Printable | implemented |
| From UNIX Timestamp | implemented |
| Fuzzy Match | implemented |
| GOST Decrypt | implemented |
| GOST Encrypt | implemented |
| GOST Hash | implemented |
| GOST Key Unwrap | implemented |
| GOST Key Wrap | implemented |
| GOST Sign | implemented |
| GOST Verify | implemented |
| Generate De Bruijn Sequence | implemented |
| Generate ECDSA Key Pair | implemented |
| Generate HOTP | implemented |
| Generate Image | implemented |
| Generate Lorem Ipsum | implemented |
| Generate PGP Key Pair | implemented |
| Generate QR Code | implemented |
| Generate RSA Key Pair | implemented |
| Generate TOTP | implemented |
| Generate UUID | implemented |
| Generate all checksums | implemented |
| Generate all hashes | implemented |
| Generic Code Beautify | implemented |
| Get All Casings | implemented |
| Get Time | implemented |
| Group IP addresses | implemented |
| Gunzip | implemented |
| Gzip | implemented |
| HAS-160 | implemented |
| HASSH Client Fingerprint | implemented |
| HASSH Server Fingerprint | implemented |
| HMAC | implemented |
| HTML To Text | implemented |
| HTTP request | implemented |
| Hamming Distance | implemented |
| Haversine distance | implemented |
| Head | implemented |
| Heatmap chart | implemented |
| Hex Density chart | implemented |
| Hex to Object Identifier | implemented |
| Hex to PEM | implemented |
| IPv6 Transition Addresses | implemented |
| Image Brightness / Contrast | implemented |
| Image Filter | implemented |
| Image Hue/Saturation/Lightness | implemented |
| Image Opacity | implemented |
| Index of Coincidence | implemented |
| Invert Image | implemented |
| JA3 Fingerprint | implemented |
| JA3S Fingerprint | implemented |
| JA4 Fingerprint | implemented |
| JA4Server Fingerprint | implemented |
| JPath expression | implemented |
| JSON Beautify | implemented |
| JSON Minify | implemented |
| JSON to CSV | implemented |
| JSON to YAML | implemented |
| JWK to PEM | implemented |
| JWT Decode | implemented |
| JWT Sign | implemented |
| JWT Verify | implemented |
| JavaScript Beautify | implemented |
| JavaScript Minify | implemented |
| JavaScript Parser | implemented |
| Jq | implemented |
| Jsonata Query | implemented |
| Jump | implemented |
| Keccak | implemented |
| LM Hash | implemented |
| LS47 Decrypt | implemented |
| LS47 Encrypt | implemented |
| LZ4 Compress | implemented |
| LZ4 Decompress | implemented |
| LZMA Compress | implemented |
| LZMA Decompress | implemented |
| LZNT1 Decompress | implemented |
| LZString Compress | implemented |
| LZString Decompress | implemented |
| Label | implemented |
| Levenshtein Distance | implemented |
| Lorenz | implemented |
| Luhn Checksum | implemented |
| MD2 | implemented |
| MD4 | implemented |
| MD5 | implemented |
| MD6 | implemented |
| MIME Decoding | implemented |
| MOD | implemented |
| Magic | implemented |
| Mean | implemented |
| Median | implemented |
| Merge | implemented |
| Microsoft Script Decoder | implemented |
| Modular Exponentiation | implemented |
| Modular Inverse | implemented |
| Multiple Bombe | implemented |
| Multiply | implemented |
| MurmurHash3 | implemented |
| NOT | implemented |
| NT Hash | implemented |
| Normalise Image | implemented |
| Normalise Unicode | implemented |
| Numberwang | implemented |
| OR | implemented |
| Object Identifier to Hex | implemented |
| Offset checker | implemented |
| Optical Character Recognition | implemented |
| P-list Viewer | implemented |
| PEM to Hex | implemented |
| PEM to JWK | implemented |
| PGP Decrypt | implemented |
| PGP Decrypt and Verify | implemented |
| PGP Encrypt | implemented |
| PGP Encrypt and Sign | implemented |
| PGP Sign | implemented |
| PGP Verify | implemented |
| PHP Deserialize | implemented |
| PHP Serialize | implemented |
| PRESENT Decrypt | implemented |
| PRESENT Encrypt | implemented |
| Pad lines | implemented |
| Parity Bit | implemented |
| Parse ASN.1 hex string | implemented |
| Parse CSR | implemented |
| Parse DateTime | implemented |
| Parse Ethernet frame | implemented |
| Parse IP range | implemented |
| Parse IPv4 header | implemented |
| Parse IPv6 address | implemented |
| Parse ObjectID timestamp | implemented |
| Parse QR Code | implemented |
| Parse SSH Host Key | implemented |
| Parse TCP | implemented |
| Parse TLS record | implemented |
| Parse TLV | implemented |
| Parse UDP | implemented |
| Parse UNIX file permissions | implemented |
| Parse URI | implemented |
| Parse User Agent | implemented |
| Parse X.509 CRL | implemented |
| Parse X.509 certificate | implemented |
| Parse colour code | implemented |
| Play Media | implemented |
| Power Set | implemented |
| Protobuf Decode | implemented |
| Protobuf Encode | implemented |
| Pseudo-Random Integer Generator | implemented |
| Pseudo-Random Number Generator | implemented |
| Pseudo-Random Prime Generator | implemented |
| Public Key from Certificate | implemented |
| Public Key from Private Key | implemented |
| RAKE | implemented |
| RC2 Decrypt | implemented |
| RC2 Encrypt | implemented |
| RC4 | implemented |
| RC4 Drop | implemented |
| RC6 Decrypt | implemented |
| RC6 Encrypt | implemented |
| RIPEMD | implemented |
| ROR13 | implemented |
| ROT13 | implemented |
| ROT13 Brute Force | implemented |
| ROT47 | implemented |
| ROT47 Brute Force | implemented |
| ROT8000 | implemented |
| RSA Decrypt | implemented |
| RSA Encrypt | implemented |
| RSA Sign | implemented |
| RSA Verify | implemented |
| Rabbit | implemented |
| Rail Fence Cipher Decode | implemented |
| Rail Fence Cipher Encode | implemented |
| Randomize Colour Palette | implemented |
| Raw Deflate | implemented |
| Raw Inflate | implemented |
| Register | implemented |
| Regular expression | implemented |
| Remove ANSI Escape Codes | implemented |
| Remove Diacritics | implemented |
| Remove EXIF | implemented |
| Remove line numbers | implemented |
| Remove null bytes | implemented |
| Remove whitespace | implemented |
| Render Image | implemented |
| Render Markdown | implemented |
| Render PDF | implemented |
| Resize Image | implemented |
| Return | implemented |
| Reverse | implemented |
| Rison Decode | implemented |
| Rison Encode | implemented |
| Rotate Image | implemented |
| Rotate left | implemented |
| Rotate right | implemented |
| SHA0 | implemented |
| SHA1 | implemented |
| SHA2 | implemented |
| SHA3 | implemented |
| SIGABA | implemented |
| SM2 Decrypt | implemented |
| SM2 Encrypt | implemented |
| SM3 | implemented |
| SM4 Decrypt | implemented |
| SM4 Encrypt | implemented |
| SQL Beautify | implemented |
| SQL Minify | implemented |
| SSDEEP | implemented |
| SUB | implemented |
| Salsa20 | implemented |
| Scan for Embedded Files | implemented |
| Scatter chart | implemented |
| Scrypt | implemented |
| Series chart | implemented |
| Set Difference | implemented |
| Set Intersection | implemented |
| Set Union | implemented |
| Shake | implemented |
| Sharpen Image | implemented |
| Show Base64 offsets | implemented |
| Show on map | implemented |
| Shuffle | implemented |
| Sleep | implemented |
| Snefru | implemented |
| Sort | implemented |
| Split | implemented |
| Split Colour Channels | implemented |
| Standard Deviation | implemented |
| Streebog | implemented |
| Strings | implemented |
| Strip HTML tags | implemented |
| Strip HTTP headers | implemented |
| Strip IPv4 header | implemented |
| Strip TCP header | implemented |
| Strip UDP header | implemented |
| Subsection | implemented |
| Substitute | implemented |
| Subtract | implemented |
| Sum | implemented |
| Swap case | implemented |
| Swap endianness | implemented |
| Symmetric Difference | implemented |
| Syntax highlighter | implemented |
| TCP/IP Checksum | implemented |
| TEA Decrypt | implemented |
| TEA Encrypt | implemented |
| Tail | implemented |
| Take bytes | implemented |
| Take nth bytes | implemented |
| Tar | implemented |
| Template | implemented |
| Text Encoding Brute Force | implemented |
| Text-Integer Conversion | implemented |
| To BCD | implemented |
| To Base | implemented |
| To Base32 | implemented |
| To Base45 | implemented |
| To Base58 | implemented |
| To Base62 | implemented |
| To Base64 | implemented |
| To Base85 | implemented |
| To Base92 | implemented |
| To Bech32 | implemented |
| To Binary | implemented |
| To Braille | implemented |
| To COBS | implemented |
| To Camel case | implemented |
| To Case Insensitive Regex | implemented |
| To Charcode | implemented |
| To Decimal | implemented |
| To Float | implemented |
| To HTML Entity | implemented |
| To Hex | implemented |
| To Hex Content | implemented |
| To Hexdump | implemented |
| To Kebab case | implemented |
| To Lower case | implemented |
| To MessagePack | implemented |
| To Modhex | implemented |
| To Morse Code | implemented |
| To Octal | implemented |
| To Punycode | implemented |
| To Quoted Printable | implemented |
| To Snake case | implemented |
| To Table | implemented |
| To UNIX Timestamp | implemented |
| To Upper case | implemented |
| Translate DateTime Format | implemented |
| Triple DES Decrypt | implemented |
| Triple DES Encrypt | implemented |
| Twofish Decrypt | implemented |
| Twofish Encrypt | implemented |
| Typex | implemented |
| UNIX Timestamp to Windows Filetime | implemented |
| URL Decode | implemented |
| URL Encode | implemented |
| Unescape Unicode Characters | implemented |
| Unescape string | implemented |
| Unicode Text Format | implemented |
| Unique | implemented |
| Untar | implemented |
| Unzip | implemented |
| VarInt Decode | implemented |
| VarInt Encode | implemented |
| View Bit Plane | implemented |
| Vigenère Decode | implemented |
| Vigenère Encode | implemented |
| Whirlpool | implemented |
| Windows Filetime to UNIX Timestamp | implemented |
| Wrap | implemented |
| XKCD Random Number | implemented |
| XML Beautify | implemented |
| XML Minify | implemented |
| XOR | implemented |
| XOR Brute Force | implemented |
| XOR Checksum | implemented |
| XPath expression | implemented |
| XSalsa20 | implemented |
| XTEA Decrypt | implemented |
| XTEA Encrypt | implemented |
| XXTEA Decrypt | implemented |
| XXTEA Encrypt | implemented |
| YAML to JSON | implemented |
| YARA Rules | implemented |
| Zip | implemented |
| Zlib Deflate | implemented |
| Zlib Inflate | implemented |
