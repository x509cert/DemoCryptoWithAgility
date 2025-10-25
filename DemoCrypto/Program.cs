using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

const byte Version1 = 1;
const byte Version2 = 2;
const byte DefaultVersion = Version2;

if (args.Length == 0 || args[0] is "-h" or "--help" or "/?" or "help")
{
    ShowHelp();
    return 0;
}

var command = args.Length > 0 ? args[0].ToLower() : "encrypt";
if (command is not ("encrypt" or "decrypt"))
{
    Console.Error.WriteLine($"Unknown command: {command}");
    ShowHelp();
    return 1;
}

if (args.Length < 4)
{
    Console.Error.WriteLine("Insufficient arguments.");
    ShowHelp();
    return 1;
}

var inputFile = args[1];
var outputFile = args[2];
var password = args[3];

byte versionToUse = DefaultVersion;
if (command == "encrypt" && args.Length > 4)
{
    if (!byte.TryParse(args[4], out versionToUse) || (versionToUse != Version1 && versionToUse != Version2))
    {
        Console.Error.WriteLine($"Invalid version: {args[4]}. Supported versions are 1 (PBKDF2) and 2 (Argon2).");
        return 1;
    }
}

if (!File.Exists(inputFile))
{
    Console.Error.WriteLine($"Input file not found: {inputFile}");
    return 1;
}

if (File.Exists(outputFile))
{
    Console.Write($"Output file '{outputFile}' already exists. Overwrite? (y/n): ");
    var response = Console.ReadLine()?.ToLower();
    if (response != "y")
    {
        Console.WriteLine("Operation cancelled.");
        return 0;
    }
}

try
{
    if (command == "encrypt")
    {
        EncryptFileWithHmac(inputFile, outputFile, password, versionToUse);
        var algorithm = versionToUse == Version1 ? "PBKDF2" : "Argon2";
        Console.WriteLine($"✓ File encrypted to {outputFile} using version {versionToUse} ({algorithm})");
    }
    else
    {
        var version = DecryptFileWithHmacVerification(inputFile, outputFile, password);
        var algorithm = version == Version1 ? "PBKDF2" : "Argon2";
        Console.WriteLine($"✓ File decrypted to {outputFile} (version {version} - {algorithm})");
    }
    return 0;
}
catch (CryptographicException ex)
{
    Console.Error.WriteLine($"Cryptographic error: {ex.Message}");
    return 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

void ShowHelp()
{
    Console.WriteLine("""
        File Encryption Utility

        Usage:
          encrypt <inputFile> <outputFile> <password> [version]  - Encrypt a file
          decrypt <inputFile> <outputFile> <password>            - Decrypt a file

        Version options:
          1 - PBKDF2 with 100,000 iterations (legacy)
          2 - Argon2id with 64MB memory (default, recommended)

        Examples:
          encrypt document.txt document.enc MyP@ssw0rd!
          encrypt document.txt document.enc MyP@ssw0rd! 2
          decrypt document.enc document.txt MyP@ssw0rd!

        Options:
          -h, --help  Show this help message
        """);
}

void EncryptFileWithHmac(string inputFile, string outputFile, string password, byte version)
{
    using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
    using var fsEncrypted = new FileStream(outputFile, FileMode.Create, FileAccess.Write);

    fsEncrypted.WriteByte(version);

    switch (version)
    {
        case Version1:
            EncryptFileWithHmacVersion1(fsInput, fsEncrypted, password);
            break;
        case Version2:
            EncryptFileWithHmacVersion2(fsInput, fsEncrypted, password);
            break;
        default:
            throw new NotSupportedException($"Encryption version {version} not implemented");
    }
}

void EncryptFileWithHmacVersion1(FileStream fsInput, FileStream fsEncrypted, string password)
{
    var salt = RandomNumberGenerator.GetBytes(32);
    fsEncrypted.Write(salt);

    using var aes = Aes.Create();
    aes.Mode = CipherMode.CBC;
    var encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        100_000,
        HashAlgorithmName.SHA256,
        32
    );
    aes.Key = encryptionKey;
    aes.IV = RandomNumberGenerator.GetBytes(16);
    fsEncrypted.Write(aes.IV);

    using (var cs = new CryptoStream(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write))
    {
        fsInput.CopyTo(cs);
    }
    
    var hmacKey = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        100_000,
        HashAlgorithmName.SHA256,
        32
    );
    
    using var hmac = new HMACSHA256(hmacKey);
    fsEncrypted.Position = 0;
    var endOfCiphertext = fsEncrypted.Length;
    var buffer = new byte[endOfCiphertext];
    fsEncrypted.ReadExactly(buffer);
    var tag = hmac.ComputeHash(buffer);
    fsEncrypted.Write(tag);
}

void EncryptFileWithHmacVersion2(FileStream fsInput, FileStream fsEncrypted, string password)
{
    var salt = RandomNumberGenerator.GetBytes(32);
    fsEncrypted.Write(salt);

    var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
    argon2.Salt = salt;
    argon2.DegreeOfParallelism = 8;
    argon2.MemorySize = 65_536; // 64 MB
    argon2.Iterations = 4;
    
    var encryptionKey = argon2.GetBytes(32);
    
    argon2.Reset();
    argon2.Salt = salt;
    argon2.DegreeOfParallelism = 8;
    argon2.MemorySize = 65_536;
    argon2.Iterations = 4;
    var hmacKey = argon2.GetBytes(32);

    using var aes = Aes.Create();
    aes.Mode = CipherMode.CBC;
    aes.Key = encryptionKey;
    aes.IV = RandomNumberGenerator.GetBytes(16);
    fsEncrypted.Write(aes.IV);

    using (var cs = new CryptoStream(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write))
    {
        fsInput.CopyTo(cs);
    }
    
    using var hmac = new HMACSHA256(hmacKey);
    fsEncrypted.Position = 0;
    var endOfCiphertext = fsEncrypted.Length;
    var buffer = new byte[endOfCiphertext];
    fsEncrypted.ReadExactly(buffer);
    var tag = hmac.ComputeHash(buffer);
    fsEncrypted.Write(tag);
}

byte DecryptFileWithHmacVerification(string inputFile, string outputFile, string password)
{
    using var fsEncrypted = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
    using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);

    var version = fsEncrypted.ReadByte();

    switch ((byte)version)
    {
        case Version1:
            DecryptFileWithHmacVerificationVersion1(fsEncrypted, fsOutput, password);
            return Version1;
        case Version2:
            DecryptFileWithHmacVerificationVersion2(fsEncrypted, fsOutput, password);
            return Version2;
        default:
            throw new NotSupportedException($"Unsupported file version: {version}");
    }
}

void DecryptFileWithHmacVerificationVersion1(FileStream fsEncrypted, FileStream fsOutput, string password)
{
    var salt = new byte[32];
    fsEncrypted.ReadExactly(salt);

    var iv = new byte[16];
    fsEncrypted.ReadExactly(iv);
    
    var hmacKey = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        100_000,
        HashAlgorithmName.SHA256,
        32
    );
    
    var fileLength = fsEncrypted.Length;
    var hmacSize = 32;
    if (fileLength < 1 + 32 + 16 + hmacSize)
    {
        throw new InvalidOperationException("File too small to contain valid encrypted data");
    }
    
    var endOfCiphertext = fileLength - hmacSize;
    var storedTag = new byte[hmacSize];
    fsEncrypted.Position = endOfCiphertext;
    fsEncrypted.ReadExactly(storedTag);
    
    using var hmac = new HMACSHA256(hmacKey);
    fsEncrypted.Position = 0;
    var buffer = new byte[endOfCiphertext];
    fsEncrypted.ReadExactly(buffer);
    var computedTag = hmac.ComputeHash(buffer);
    
    if (!CryptographicOperations.FixedTimeEquals(computedTag, storedTag))
    {
        throw new CryptographicException("Authentication failed - file may be corrupted or tampered with");
    }
    
    fsEncrypted.Position = 1 + 32 + 16;

    using var aes = Aes.Create();
    aes.Mode = CipherMode.CBC;
    var encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        100_000,
        HashAlgorithmName.SHA256,
        32
    );
    aes.Key = encryptionKey;
    aes.IV = iv;

    var ciphertextLength = endOfCiphertext - fsEncrypted.Position;
    using var cs = new CryptoStream(fsEncrypted, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fsOutput);
}

void DecryptFileWithHmacVerificationVersion2(FileStream fsEncrypted, FileStream fsOutput, string password)
{
    var salt = new byte[32];
    fsEncrypted.ReadExactly(salt);

    var iv = new byte[16];
    fsEncrypted.ReadExactly(iv);
    
    var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
    argon2.Salt = salt;
    argon2.DegreeOfParallelism = 8;
    argon2.MemorySize = 65_536; // 64 MB
    argon2.Iterations = 4;
    var hmacKey = argon2.GetBytes(32);
    
    var fileLength = fsEncrypted.Length;
    var hmacSize = 32;
    if (fileLength < 1 + 32 + 16 + hmacSize)
    {
        throw new InvalidOperationException("File too small to contain valid encrypted data");
    }
    
    var endOfCiphertext = fileLength - hmacSize;
    var storedTag = new byte[hmacSize];
    fsEncrypted.Position = endOfCiphertext;
    fsEncrypted.ReadExactly(storedTag);
    
    using var hmac = new HMACSHA256(hmacKey);
    fsEncrypted.Position = 0;
    var buffer = new byte[endOfCiphertext];
    fsEncrypted.ReadExactly(buffer);
    var computedTag = hmac.ComputeHash(buffer);
    
    if (!CryptographicOperations.FixedTimeEquals(computedTag, storedTag))
    {
        throw new CryptographicException("Authentication failed - file may be corrupted or tampered with");
    }
    
    argon2.Reset();
    argon2.Salt = salt;
    argon2.DegreeOfParallelism = 8;
    argon2.MemorySize = 65_536;
    argon2.Iterations = 4;
    var encryptionKey = argon2.GetBytes(32);
    
    fsEncrypted.Position = 1 + 32 + 16;

    using var aes = Aes.Create();
    aes.Mode = CipherMode.CBC;
    aes.Key = encryptionKey;
    aes.IV = iv;

    var ciphertextLength = endOfCiphertext - fsEncrypted.Position;
    using var cs = new CryptoStream(fsEncrypted, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fsOutput);
}
