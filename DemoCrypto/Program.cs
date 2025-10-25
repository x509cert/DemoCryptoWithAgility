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
        CheckPasswordComplexity(password);
        EncryptFileWithHmac(inputFile, outputFile, password, versionToUse);
        var algorithm = versionToUse == Version1 ? "PBKDF2" : "Argon2";
        Console.WriteLine($"File encrypted to {outputFile} using version {versionToUse} ({algorithm})");
    }
    else
    {
        var version = DecryptFileWithHmacVerification(inputFile, outputFile, password);
        var algorithm = version == Version1 ? "PBKDF2" : "Argon2";
        Console.WriteLine($"File decrypted to {outputFile} (version {version} - {algorithm})");
    }
    return 0;
}
catch (CryptographicException ex)
{
    Console.Error.WriteLine($"Cryptographic error: {ex.Message}");
    if (ex.Message.Contains("Padding"))
    {
        Console.Error.WriteLine("This usually means the password is incorrect.");
    }
    return 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

void CheckPasswordComplexity(string password)
{
    var hasUpper = false;
    var hasLower = false;
    var hasDigit = false;
    var hasSpecial = false;

    foreach (var c in password)
    {
        if (char.IsUpper(c)) hasUpper = true;
        else if (char.IsLower(c)) hasLower = true;
        else if (char.IsDigit(c)) hasDigit = true;
        else if (!char.IsLetterOrDigit(c)) hasSpecial = true;
    }

    var complexityScore = 0;
    if (hasUpper) complexityScore++;
    if (hasLower) complexityScore++;
    if (hasDigit) complexityScore++;
    if (hasSpecial) complexityScore++;

    if (password.Length < 8)
    {
        Console.WriteLine("Warning: Password is less than 8 characters. Consider using a longer password for better security.");
        Console.WriteLine();
    }
    else if (password.Length < 12 && complexityScore < 3)
    {
        Console.WriteLine("Warning: Password has low complexity. Consider using a mix of uppercase, lowercase, numbers, and symbols.");
        Console.WriteLine();
    }
    else if (password == "password" || password == "Password123" || password == "12345678" || password == "password123")
    {
        Console.WriteLine("Warning: This is a commonly used password that appears in breach databases. Please use a unique password.");
        Console.WriteLine();
    }
    else if (!hasUpper || !hasLower)
    {
        Console.WriteLine("Warning: Password should contain both uppercase and lowercase letters for better security.");
        Console.WriteLine();
    }
    else if (!hasDigit && !hasSpecial)
    {
        Console.WriteLine("Warning: Consider adding numbers or special characters to increase password strength.");
        Console.WriteLine();
    }
    else if (password.Length < 12)
    {
        Console.WriteLine("Note: Password meets minimum requirements but using 12+ characters is recommended.");
        Console.WriteLine();
    }
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
    using var fsEncrypted = new FileStream(outputFile, FileMode.Create, FileAccess.ReadWrite);

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
    aes.Padding = PaddingMode.PKCS7;
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

    using (var cs = new CryptoStream(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
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
    aes.Padding = PaddingMode.PKCS7;
    aes.Key = encryptionKey;
    aes.IV = RandomNumberGenerator.GetBytes(16);
    fsEncrypted.Write(aes.IV);

    using (var cs = new CryptoStream(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
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
    aes.Padding = PaddingMode.PKCS7;
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
    using var limitedStream = new LimitedStream(fsEncrypted, ciphertextLength);
    using var cs = new CryptoStream(limitedStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
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
    aes.Padding = PaddingMode.PKCS7;
    aes.Key = encryptionKey;
    aes.IV = iv;

    var ciphertextLength = endOfCiphertext - fsEncrypted.Position;
    using var limitedStream = new LimitedStream(fsEncrypted, ciphertextLength);
    using var cs = new CryptoStream(limitedStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fsOutput);
}

class LimitedStream : Stream
{
    private readonly Stream _baseStream;
    private readonly long _length;
    private long _position;

    public LimitedStream(Stream baseStream, long length)
    {
        _baseStream = baseStream;
        _length = length;
        _position = 0;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _position; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var toRead = (int)Math.Min(count, _length - _position);
        if (toRead <= 0) return 0;
        
        var bytesRead = _baseStream.Read(buffer, offset, toRead);
        _position += bytesRead;
        return bytesRead;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}