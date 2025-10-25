# DemoCrypto - File Encryption Utility with Cryptographic Agility

A .NET command-line file encryption/decryption utility demonstrating **cryptographic agility** - the ability to support multiple encryption algorithms and seamlessly migrate between them as security requirements evolve.

## 🔐 What is Cryptographic Agility?

Cryptographic agility is a critical security practice that allows systems to:
- **Adapt to evolving threats** by upgrading to stronger algorithms
- **Support legacy data** encrypted with older algorithms
- **Migrate gradually** from weak to strong cryptography
- **Future-proof applications** against cryptographic advances

This project demonstrates crypto agility by supporting three different encryption versions, each representing a security evolution:

| Version | Algorithm | Key Derivation | Security Level | Use Case |
|---------|-----------|----------------|----------------|----------|
| **Version 1** | AES-ECB | PBKDF2 (10k iterations) | ⚠️ Legacy | Backward compatibility only |
| **Version 2** | AES-CBC | PBKDF2 (100k iterations) | ✅ Good | Transitional security |
| **Version 3** | AES-CBC | Argon2 (64MB) | ✨ Recommended | Modern best practice |

The utility automatically detects which version was used to encrypt a file and applies the correct decryption method, while always defaulting to the most secure version for new encryptions.

## ✨ Features

### Cryptographic Features
- **Multiple encryption versions** with automatic version detection
- **AES-256 encryption** across all versions
- **HMAC-SHA256 authentication** for tamper detection
- **Argon2id** (Version 3) - memory-hard KDF resistant to GPU attacks
- **PBKDF2-SHA256** (Versions 1 & 2) - industry-standard key derivation
- **Cryptographically secure random** salt and IV generation
- **Constant-time comparison** for HMAC verification (timing attack protection)

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
git clone https://github.com/x509cert/DemoCryptoNoAgility.git
cd DemoCryptoNoAgility
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

**Encrypt a file** (defaults to Version 3 - Argon2id):
```bash
dotnet run -- encrypt document.txt document.enc "MySecureP@ssw0rd!"
```

**Encrypt with a specific version**:
```bash
dotnet run -- encrypt document.txt document.enc "MySecureP@ssw0rd!" 2
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
# Encrypt with latest version (Argon2id)
dotnet run -- encrypt secret.txt secret.enc "Str0ng!Pass"

# Inspect the encrypted file
dotnet run -- dump secret.enc
# Output shows: Version 3 (AES-CBC with Argon2id)

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

### Version 2 & 3 (AES-CBC) - 81 bytes overhead
```
┌────────┬─────────────┬────────┬─────────────┬──────────────┐
│Version │    Salt     │   IV   │ Ciphertext  │  HMAC-SHA256 │
│ 1 byte │  32 bytes   │16 bytes│  Variable   │   32 bytes   │
└────────┴─────────────┴────────┴─────────────┴──────────────┘
```

**Key Design Features:**
- **Version byte** at the start enables format evolution
- **Salt** ensures unique keys even with same password
- **IV** (Versions 2 & 3) ensures semantic security
- **HMAC** at the end provides authenticated encryption (Encrypt-then-MAC)

## 🔒 Security Details

### Version 3 (Recommended) - Argon2id
- **Algorithm**: AES-256-CBC
- **Mode**: CBC with random IV
- **KDF**: Argon2id
  - Memory: 64 MB (65,536 KiB)
  - Iterations: 4
  - Parallelism: 8 threads
  - Salt: 32 bytes (random)
- **Authentication**: HMAC-SHA256
- **Padding**: PKCS7

**Why Argon2id?**
- Memory-hard design resists GPU/ASIC attacks
- Winner of Password Hashing Competition (2015)
- Recommended by OWASP for password storage
- Configurable parameters for future upgrades

### Version 2 - PBKDF2 (100k iterations)
- **Algorithm**: AES-256-CBC
- **Mode**: CBC with random IV
- **KDF**: PBKDF2-HMAC-SHA256
  - Iterations: 100,000
  - Salt: 32 bytes (random)
- **Authentication**: HMAC-SHA256
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
}
```

### Key Components

- **`LimitedStream`**: Custom stream wrapper that prevents reading beyond ciphertext boundaries during decryption, ensuring the HMAC bytes aren't fed into the decryptor
- **Encrypt-then-MAC**: HMAC is computed over the entire encrypted file (excluding HMAC itself), providing authenticated encryption
- **Separate keys**: Encryption and HMAC keys are derived independently from the password
- **Stream processing**: Efficient memory usage for files of any size

## 🐛 Troubleshooting

### Common Errors

**"Padding is invalid and cannot be removed"**
- **Cause**: Incorrect password, or file corruption
- **Solution**: Double-check password, verify file integrity

**"Authentication failed - file may be corrupted or tampered with"**
- **Cause**: HMAC verification failed
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
- IV (hex, if applicable)
- First 64 bytes of ciphertext (hex dump)
- HMAC tag (hex)

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
│   ├── Constants              # Version definitions
│   ├── Command-Line Parsing   # Argument handling
│   ├── File Validation        # Input/output checks
│   ├── Main Execution         # Encrypt/decrypt flow
│   ├── Helper Methods         # Dump, password check, help
│   ├── Encryption Methods     # Version-specific encryption
│   ├── Decryption Methods     # Version-specific decryption
│   └── Support Classes        # LimitedStream
└── README.md                  # This file
```

## 🤝 Contributing

Contributions are welcome! Areas for enhancement:

- [ ] Add AES-GCM mode (Version 4) for AEAD
- [ ] Support for ChaCha20-Poly1305
- [ ] Key rotation utilities
- [ ] Batch encryption/decryption
- [ ] Progress indicators for large files
- [ ] Configuration file for custom KDF parameters
- [ ] Unit tests and integration tests
- [ ] Benchmarking suite for version comparison

Please ensure all contributions follow security best practices.

## 📚 Additional Resources

### Cryptographic Standards & Guidelines
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

**Not audited for production use.** For enterprise or mission-critical applications:
- Use established tools (GPG, age, OpenSSL)
- Conduct professional security audits
- Follow your organization's security policies
- Comply with relevant regulations (GDPR, HIPAA, etc.)

**Legal Compliance**: Ensure encryption usage complies with your local laws and export control regulations.

## 📄 License

This project is provided as-is under the MIT License for educational and practical use.

---

**Built with .NET 10** | **Demonstrating Cryptographic Agility** | **Security by Design**
