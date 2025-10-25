# DemoCrypto - File Encryption Utility with Cryptographic Agility

A .NET command-line file encryption/decryption utility demonstrating **cryptographic agility** - the ability to support multiple encryption algorithms and seamlessly migrate between them as security requirements evolve.

## 🔐 What is Cryptographic Agility?

Cryptographic agility is a critical security practice that allows systems to:
- **Adapt to evolving threats** by upgrading to stronger algorithms
- **Support legacy data** encrypted with older algorithms
- **Migrate gradually** from weak to strong cryptography
- **Future-proof applications** against cryptographic advances

This project demonstrates crypto agility by supporting four different encryption versions, each representing a security evolution:

| Version | Algorithm | Key Derivation | Security Level | Use Case |
|---------|-----------|----------------|----------------|----------|
| **Version 1** | AES-ECB | PBKDF2 (10k iterations) | ⚠️ Legacy | Backward compatibility only |
| **Version 2** | AES-CBC + HMAC | PBKDF2 (100k iterations) | ✅ Good | Transitional security |
| **Version 3** | AES-CBC + HMAC | Argon2 (64MB) | ✅ Better | Modern CBC with Argon2 |
| **Version 4** | AES-GCM (AEAD) | Argon2 (64MB) | ✨ Recommended | Modern authenticated encryption |

The utility automatically detects which version was used to encrypt a file and applies the correct decryption method, while always defaulting to the most secure version for new encryptions.

## ✨ Features

### Cryptographic Features
- **Multiple encryption versions** with automatic version detection
- **AES-256 encryption** across all versions
- **AES-GCM (Version 4)** - Authenticated Encryption with Associated Data (AEAD)
- **HMAC-SHA256 authentication** (Versions 1-3) for tamper detection
- **Argon2id** (Versions 3 & 4) - memory-hard KDF resistant to GPU attacks
- **PBKDF2-SHA256** (Versions 1 & 2) - industry-standard key derivation
- **Cryptographically secure random** salt, IV, and nonce generation
- **Constant-time comparison** for authentication tag verification (timing attack protection)

### User Features
- **Password complexity checking** with actionable warnings
- **File metadata dump** command for inspection
- **Console output support** (use `con` as output file)
- **Overwrite protection** with confirmation prompts
- **Detailed error messages** for troubleshooting
- **Stream-based processing** for memory efficiency

## 📋 Prerequisites

- **.NET 10 or later**
- **Konscious.Security.Cryptography.Argon2** NuGet package (v1.3.1)

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/x509cert/DemoCryptoWithAgility.git
cd DemoCryptoWithAgility
```

### 2. Restore Dependencies
```bash
cd DemoCrypto
dotnet restore
```

The project requires the following NuGet package:
```xml
<PackageReference Include="Konscious.Security.Cryptography.Argon2" Version="1.3.1" />
```

### 3. Build the Project
```bash
dotnet build -c Release
```

## 💻 Usage

### Basic Commands

**Encrypt a file** (defaults to Version 4 - AES-GCM with Argon2id):
```bash
dotnet run -- encrypt document.txt document.enc "MySecureP@ssw0rd!"
```

**Encrypt with a specific version**:
```bash
dotnet run -- encrypt document.txt document.enc "MySecureP@ssw0rd!" 3
```

**Decrypt a file** (automatically detects version):
```bash
dotnet run -- decrypt document.enc document.txt "MySecureP@ssw0rd!"
```

**Decrypt to console** (quick view without creating file):
```bash
dotnet run -- decrypt document.enc con "MySecureP@ssw0rd!"
```

**Dump encrypted file metadata**:
```bash
dotnet run -- dump document.enc
```

**Show help**:
```bash
dotnet run -- --help
```

### Example Workflow

```bash
# Encrypt with latest version (AES-GCM + Argon2id)
dotnet run -- encrypt secret.txt secret.enc "Str0ng!Pass"

# Inspect the encrypted file
dotnet run -- dump secret.enc
# Output shows: Version 4 (AES-GCM with Argon2id AEAD)

# Decrypt the file
dotnet run -- decrypt secret.enc secret-decrypted.txt "Str0ng!Pass"

# Quick view in console
dotnet run -- decrypt secret.enc con "Str0ng!Pass"
```

## 📦 File Format Specification

The encrypted file format is version-aware, enabling cryptographic agility:

### Version 1 (AES-ECB/PBKDF2-10k) - 65 bytes overhead
```
┌────────┬─────────────┬─────────────┬──────────────┐
│Version │    Salt     │ Ciphertext  │  HMAC-SHA256 │
│ 1 byte │  32 bytes   │  Variable   │   32 bytes   │
└────────┴─────────────┴─────────────┴──────────────┘
```

### Version 2 & 3 (AES-CBC + HMAC) - 81 bytes overhead
```
┌────────┬─────────────┬────────┬─────────────┬──────────────┐
│Version │    Salt     │   IV   │ Ciphertext  │  HMAC-SHA256 │
│ 1 byte │  32 bytes   │16 bytes│  Variable   │   32 bytes   │
└────────┴─────────────┴────────┴─────────────┴──────────────┘
```

### Version 4 (AES-GCM AEAD) - 61 bytes overhead
```
┌────────┬─────────────┬─────────┬─────────────┬──────────────┐
│Version │    Salt     │  Nonce  │ Ciphertext  │   GCM Tag    │
│ 1 byte │  32 bytes   │12 bytes │  Variable   │   16 bytes   │
└────────┴─────────────┴─────────┴─────────────┴──────────────┘
```

**Key Design Features:**
- **Version byte** at the start enables format evolution
- **Salt** ensures unique keys even with same password
- **IV/Nonce** ensures semantic security
- **Authentication tags** provide authenticated encryption
- **GCM (Version 4)** provides both confidentiality and authenticity in a single operation (AEAD)

## 🔒 Security Details

### Version 4 (Recommended) - AES-GCM AEAD ✨
- **Algorithm**: AES-256-GCM
- **Mode**: GCM (Galois/Counter Mode) - AEAD
- **Nonce**: 12 bytes (96 bits - optimal for GCM)
- **Authentication Tag**: 16 bytes (128 bits)
- **KDF**: Argon2id
  - Memory: 64 MB (65,536 KiB)
  - Iterations: 4
  - Parallelism: 8 threads
  - Salt: 32 bytes (random)
- **No padding required** (stream cipher mode)

**Why AES-GCM?**
- Single-pass authenticated encryption (faster than CBC+HMAC)
- AEAD (Authenticated Encryption with Associated Data)
- No padding oracle attacks (stream cipher mode)
- Hardware acceleration on modern CPUs (AES-NI + PCLMULQDQ)
- Recommended by NIST SP 800-38D
- Industry standard for TLS 1.3, QUIC, and IPsec

### Version 3 - Argon2id + CBC + HMAC
- **Algorithm**: AES-256-CBC
- **Mode**: CBC with random IV
- **KDF**: Argon2id
  - Memory: 64 MB (65,536 KiB)
  - Iterations: 4
  - Parallelism: 8 threads
  - Salt: 32 bytes (random)
- **Authentication**: HMAC-SHA256 (Encrypt-then-MAC)
- **Padding**: PKCS7

**Why Argon2id?**
- Memory-hard design resists GPU/ASIC attacks
- Winner of Password Hashing Competition (2015)
- Recommended by OWASP for password storage
- Configurable parameters for future upgrades

### Version 2 - PBKDF2 (100k iterations) + CBC + HMAC
- **Algorithm**: AES-256-CBC
- **Mode**: CBC with random IV
- **KDF**: PBKDF2-HMAC-SHA256
  - Iterations: 100,000
  - Salt: 32 bytes (random)
- **Authentication**: HMAC-SHA256 (Encrypt-then-MAC)
- **Padding**: PKCS7

**Migration Path**: Version 2 provides a middle ground for environments where Argon2 may have compatibility concerns.

### Version 1 (Legacy) - ⚠️ Not Recommended
- **Algorithm**: AES-256-ECB
- **Mode**: ECB (⚠️ patterns in plaintext leak into ciphertext)
- **KDF**: PBKDF2-HMAC-SHA256
  - Iterations: 10,000 (⚠️ vulnerable to brute force)
  - Salt: 32 bytes (random)
- **Authentication**: HMAC-SHA256
- **Padding**: PKCS7

**Use Case**: Version 1 exists solely for demonstrating legacy compatibility in crypto-agile systems. **Never use ECB mode in production.**

### Password Recommendations

The utility provides real-time warnings for:
- ❌ Passwords < 8 characters
- ❌ Low complexity (missing character types)
- ❌ Common breached passwords (password, Password123, etc.)
- ⚠️ Missing uppercase/lowercase mix
- ⚠️ No digits or special characters
- ℹ️ Passwords < 12 characters (though passing minimum)

**Best Practices:**
- Use **12+ characters**
- Include **uppercase, lowercase, digits, and symbols**
- Avoid **dictionary words** and **personal information**
- Use a **password manager** for unique, random passwords
- Consider **passphrases** (e.g., "correct-horse-battery-staple")

## 🏗️ Architecture

### Cryptographic Agility Implementation

The code demonstrates clean separation of version-specific logic:

```csharp
// Version detection on decryption
var version = fsEncrypted.ReadByte();
switch ((byte)version)
{
    case Version1: DecryptVersion1(...); break;
    case Version2: DecryptVersion2(...); break;
    case Version3: DecryptVersion3(...); break;
    case Version4: DecryptVersion4(...); break; // GCM AEAD
}
```

### Key Components

- **`LimitedStream`**: Custom stream wrapper that prevents reading beyond ciphertext boundaries during decryption (used by CBC versions)
- **Encrypt-then-MAC** (Versions 1-3): HMAC is computed over the entire encrypted file (excluding HMAC itself)
- **AEAD** (Version 4): GCM provides integrated authentication, eliminating the need for separate HMAC
- **Separate keys** (Versions 1-3): Encryption and HMAC keys are derived independently from the password
- **Single key** (Version 4): GCM uses one key for both encryption and authentication
- **Stream processing**: Efficient memory usage for files of any size

### Performance Comparison

| Version | Mode | Operations | Relative Speed | Security Level |
|---------|------|------------|----------------|----------------|
| Version 1 | ECB + HMAC | Encrypt + Hash | Baseline | ⚠️ Weak |
| Version 2 | CBC + HMAC | Encrypt + Hash | ~1.0x | Good |
| Version 3 | CBC + HMAC | Encrypt + Hash + Argon2 | ~1.0x | Better |
| Version 4 | GCM AEAD | Single-pass | **~1.5-2x** 🚀 | Best |

*Note: Version 4 (GCM) is typically faster than CBC+HMAC due to single-pass operation and hardware acceleration.*

## 🐛 Troubleshooting

### Common Errors

**"Padding is invalid and cannot be removed"** (Versions 1-3)
- **Cause**: Incorrect password, or file corruption
- **Solution**: Double-check password, verify file integrity

**"Authentication failed - file may be corrupted, tampered with, or password is incorrect"**
- **Cause**: Authentication tag/HMAC verification failed
- **Possible reasons**:
  - Wrong password
  - File was modified after encryption
  - File corruption during transfer
- **Solution**: Verify password, check file integrity, re-download if transferred

**"File too small to contain valid encrypted data"**
- **Cause**: File is truncated or not an encrypted file
- **Solution**: Verify file was encrypted with this tool, check for transfer errors

**"Unsupported file version: X"**
- **Cause**: File was encrypted with an unknown version
- **Solution**: Ensure file was created by this tool, check for corruption

### Debugging with Dump Command

Use the `dump` command to inspect encrypted files:

```bash
dotnet run -- dump myfile.enc
```

Output includes:
- File version and algorithm
- Salt (hex)
- IV/Nonce (hex, depending on version)
- First 64 bytes of ciphertext (hex dump)
- Authentication tag (HMAC or GCM tag, hex)

## 🛠️ Development

### Building from Source

```bash
# Debug build
dotnet build

# Release build
dotnet build -c Release

# Run tests (if available)
dotnet test
```

### Creating Standalone Executables

```bash
# Windows
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Linux
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true

# macOS
dotnet publish -c Release -r osx-x64 --self-contained true -p:PublishSingleFile=true
```

### Project Structure

```
DemoCrypto/
├── DemoCrypto.csproj          # .NET 10 project file
├── Program.cs                 # Main application logic
│   ├── Constants              # Version definitions (1-4)
│   ├── Command-Line Parsing   # Argument handling
│   ├── File Validation        # Input/output checks
│   ├── Main Execution         # Encrypt/decrypt flow
│   ├── Helper Methods         # Dump, password check, help
│   ├── Encryption Methods     # Version-specific encryption
│   ├── Decryption Methods     # Version-specific decryption
│   └── Support Classes        # LimitedStream
└── README.md                  # This file
```

## 🤝 Further Ideas

Areas for enhancement:

- [x] Add AES-GCM mode (Version 4) for AEAD ✅
- [ ] Support for ChaCha20-Poly1305 (Version 5)
- [ ] Support for XChaCha20-Poly1305
- [ ] Key rotation utilities
- [ ] Batch encryption/decryption
- [ ] Progress indicators for large files
- [ ] Configuration file for custom KDF parameters
- [ ] Unit tests and integration tests
- [ ] Benchmarking suite for version comparison
- [ ] Associated data (AAD) support for GCM

Please ensure all contributions follow security best practices.

## 📚 Additional Resources

### Cryptographic Standards & Guidelines
- [NIST SP 800-38D: GCM Recommendation](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-132: PBKDF Recommendations](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [FIPS 197: AES Specification](https://csrc.nist.gov/publications/detail/fips/197/final)

### Related Projects
- [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography) - Argon2 for .NET
- [age](https://github.com/FiloSottile/age) - Modern file encryption tool
- [GPG](https://gnupg.org/) - GNU Privacy Guard

## ⚠️ Security Notice

**Educational and Personal Use**

This utility is designed for:
- **Educational purposes** - demonstrating cryptographic agility concepts
- **Personal file encryption** - protecting local files
- **Development/testing** - understanding encryption workflows

## 📄 License

This project is provided as-is under the MIT License for educational and practical use.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/x509cert/DemoCryptoNoAgility/issues)
- **Discussions**: [GitHub Discussions](https://github.com/x509cert/DemoCryptoNoAgility/discussions)

---

**Built with .NET 10** | **Demonstrating Cryptographic Agility** | **Security by Design** | **Now with AES-GCM AEAD!** 🔐
