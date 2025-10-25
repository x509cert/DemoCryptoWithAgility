using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

const byte Version1 = 1;
const byte Version2 = 2;
const byte Version3 = 3;
const byte DefaultVersion = Version3;

if (args.Length == 0 || args[0] is "-h" or "--help" or "/?" or "help")
{
    ShowHelp();
    return 0;
}

var command = args.Length > 0 ? args[0].ToLower() : "encrypt";
if (command is not ("encrypt" or "decrypt" or "dump"))
{
    Console.Error.WriteLine($"Unknown command: {command}");
    ShowHelp();
    return 1;
}

if (command == "dump")
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Insufficient arguments for dump command.");
        ShowHelp();
        return 1;
    }
    
    var dumpFile = args[1];
    if (!File.Exists(dumpFile))
    {
        Console.Error.WriteLine($"Input file not found: {dumpFile}");
        return 1;
    }
    
    try
    {
        DumpEncryptedFile(dumpFile);
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error dumping file: {ex.Message}");
        return 1;
    }
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
    if (!byte.TryParse(args[4], out versionToUse) || (versionToUse != Version1 && versionToUse != Version2 && versionToUse != Version3))
    {
        Console.Error.WriteLine($"Invalid version: {args[4]}. Supported versions are 1 (AES-ECB/PBKDF2-10k), 2 (AES-CBC/PBKDF2-100k), and 3 (AES-CBC/Argon2).");
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
        var algorithm = versionToUse switch
        {
            Version1 => "AES-ECB with PBKDF2 (10k iterations)",
            Version2 => "AES-CBC with PBKDF2 (100k iterations)",
            Version3 => "AES-CBC with Argon2id",
            _ => "Unknown"
        };
        Console.WriteLine($"File encrypted to {outputFile} using version {versionToUse} ({algorithm})");
    }
    else
    {
        var version = DecryptFileWithHmacVerification(inputFile, outputFile, password);
        var algorithm = version switch
        {
            Version1 => "AES-ECB with PBKDF2 (10k iterations)",
            Version2 => "AES-CBC with PBKDF2 (100k iterations)",
            Version3 => "AES-CBC with Argon2id",
            _ => "Unknown"
        };
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

void DumpEncryptedFile(string inputFile)
{
    using var fs = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
    
    if (fs.Length < 1)
    {
        throw new InvalidOperationException("File is empty");
    }
    
    var version = (byte)fs.ReadByte();
    Console.WriteLine($"=== Encrypted File Dump ===");
    Console.WriteLine($"File: {inputFile}");
    Console.WriteLine($"File Size: {fs.Length} bytes");
    Console.WriteLine($"Version: {version}");
    Console.WriteLine($"Algorithm: {version switch
    {
        Version1 => "AES-ECB with PBKDF2 (10k iterations)",
        Version2 => "AES-CBC with PBKDF2 (100k iterations)",
        Version3 => "AES-CBC with Argon2id",
        _ => "Unknown"
    }}");
    Console.WriteLine();
    
    if (fs.Length < 33)
    {
        Console.WriteLine("File too small to contain valid encrypted data");
        return;
    }
    
    var salt = new byte[32];
    fs.ReadExactly(salt);
    Console.WriteLine($"Salt (32 bytes):");
    Console.WriteLine($"  {Convert.ToHexString(salt)}");
    Console.WriteLine();
    
    if (version == Version2 || version == Version3)
    {
        if (fs.Length < 49)
        {
            Console.WriteLine("File too small to contain IV");
            return;
        }
        
        var iv = new byte[16];
        fs.ReadExactly(iv);
        Console.WriteLine($"IV (16 bytes):");
        Console.WriteLine($"  {Convert.ToHexString(iv)}");
        Console.WriteLine();
    }
    else if (version == Version1)
    {
        Console.WriteLine("IV: Not used (ECB mode)");
        Console.WriteLine();
    }
    
    var currentPosition = fs.Position;
    var hmacSize = 32;
    var ciphertextLength = fs.Length - currentPosition - hmacSize;
    
    if (ciphertextLength <= 0)
    {
        Console.WriteLine("No ciphertext found");
        return;
    }
    
    Console.WriteLine($"Ciphertext starts at byte: {currentPosition}");
    Console.WriteLine($"Ciphertext length: {ciphertextLength} bytes");
    
    var bytesToRead = (int)Math.Min(64, ciphertextLength);
    var ciphertextSample = new byte[bytesToRead];
    fs.ReadExactly(ciphertextSample);
    
    Console.WriteLine($"First {bytesToRead} bytes of ciphertext:");
    for (int i = 0; i < bytesToRead; i += 16)
    {
        var lineLength = Math.Min(16, bytesToRead - i);
        var lineBytes = new byte[lineLength];
        Array.Copy(ciphertextSample, i, lineBytes, 0, lineLength);
        Console.WriteLine($"  {i:X4}: {Convert.ToHexString(lineBytes)}");
    }
    Console.WriteLine();
    
    fs.Position = fs.Length - hmacSize;
    var hmac = new byte[hmacSize];
    fs.ReadExactly(hmac);
    Console.WriteLine($"HMAC-SHA256 (32 bytes):");
    Console.WriteLine($"  {Convert.ToHexString(hmac)}");
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
          dump <inputFile>                                        - Dump encrypted file metadata

        Version options:
          1 - AES-ECB with PBKDF2 10,000 iterations (legacy, least secure)
          2 - AES-CBC with PBKDF2 100,000 iterations (better)
          3 - AES-CBC with Argon2id 64MB memory (default, recommended)

        Examples:
          encrypt document.txt document.enc MyP@ssw0rd!
          encrypt document.txt document.enc MyP@ssw0rd! 3
          decrypt document.enc document.txt MyP@ssw0rd!
          dump document.enc

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
        case Version3:
            EncryptFileWithHmacVersion3(fsInput, fsEncrypted, password);
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
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.PKCS7;
    var encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        10_000,
        HashAlgorithmName.SHA256,
        32
    );
    aes.Key = encryptionKey;
    // ECB mode doesn't use IV

    using (var cs = new CryptoStream(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
    {
        fsInput.CopyTo(cs);
    }

    var hmacKey = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        10_000,
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

void EncryptFileWithHmacVersion3(FileStream fsInput, FileStream fsEncrypted, string password)
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
        case Version3:
            DecryptFileWithHmacVerificationVersion3(fsEncrypted, fsOutput, password);
            return Version3;
        default:
            throw new NotSupportedException($"Unsupported file version: {version}");
    }
}

void DecryptFileWithHmacVerificationVersion1(FileStream fsEncrypted, FileStream fsOutput, string password)
{
    var salt = new byte[32];
    fsEncrypted.ReadExactly(salt);

    // No IV for ECB mode

    var hmacKey = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        10_000,
        HashAlgorithmName.SHA256,
        32
    );

    var fileLength = fsEncrypted.Length;
    var hmacSize = 32;
    if (fileLength < 1 + 32 + hmacSize)
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

    fsEncrypted.Position = 1 + 32;

    using var aes = Aes.Create();
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.PKCS7;
    var encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        10_000,
        HashAlgorithmName.SHA256,
        32
    );
    aes.Key = encryptionKey;

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

void DecryptFileWithHmacVerificationVersion3(FileStream fsEncrypted, FileStream fsOutput, string password)
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