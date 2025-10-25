using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

#region Constants
const byte V1_AES_ECB_HMAC_PBKDF2_10K = 1;
const byte V2_AES_CBC_HMAC_PBKDF2_100K = 2;
const byte V3_AES_CBC_HMAC_Argon2 = 3;
const byte V4_AES_GCM_Argon2 = 4;
const byte DefaultVersion = V4_AES_GCM_Argon2;
#endregion

#region Command-Line Parsing
if (args.Length == 0 || args[0] is "-h" or "--help" or "/?" or "help")
{
    ShowHelp();
    return 0;
}

// Check for force flag
var forceOverwrite = args.Any(a => a is "-f" or "--force");
var argsWithoutForce = args.Where(a => a is not "-f" and not "--force").ToArray();

var command = argsWithoutForce.Length > 0 ? argsWithoutForce[0].ToLower() : "encrypt";
if (command is not ("encrypt" or "decrypt" or "dump"))
{
    Console.Error.WriteLine($"Unknown command: {command}");
    ShowHelp();
    return 1;
}

if (command == "dump")
{
    if (argsWithoutForce.Length < 2)
    {
        Console.Error.WriteLine("Insufficient arguments for dump command.");
        ShowHelp();
        return 1;
    }
    
    var dumpFile = argsWithoutForce[1];
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

// For encrypt command, require version; for decrypt, require 4 args
var requiredArgs = command == "encrypt" ? 5 : 4;
if (argsWithoutForce.Length < requiredArgs)
{
    Console.Error.WriteLine($"Insufficient arguments for {command} command.");
    ShowHelp();
    return 1;
}

var inputFile = argsWithoutForce[1];
var outputFile = argsWithoutForce[2];
var password = argsWithoutForce[3];

byte versionToUse = DefaultVersion;
if (command == "encrypt")
{
    if (!byte.TryParse(argsWithoutForce[4], out versionToUse) || 
        (versionToUse != V1_AES_ECB_HMAC_PBKDF2_10K && 
         versionToUse != V2_AES_CBC_HMAC_PBKDF2_100K && 
         versionToUse != V3_AES_CBC_HMAC_Argon2 && 
         versionToUse != V4_AES_GCM_Argon2))
    {
        Console.Error.WriteLine($"Invalid version: {argsWithoutForce[4]}. Supported versions are 1 (AES-ECB/PBKDF2-10k), 2 (AES-CBC/PBKDF2-100k), 3 (AES-CBC/Argon2), and 4 (AES-GCM/Argon2).");
        return 1;
    }
}
#endregion

#region File Validation
if (!File.Exists(inputFile))
{
    Console.Error.WriteLine($"Input file not found: {inputFile}");
    return 1;
}

if (File.Exists(outputFile) && !forceOverwrite)
{
    Console.Write($"Output file '{outputFile}' already exists. Overwrite? (y/n): ");
    var response = Console.ReadLine()?.ToLower();
    if (response != "y")
    {
        Console.WriteLine("Operation cancelled.");
        return 0;
    }
}
#endregion

#region Main Execution
try
{
    if (command == "encrypt")
    {
        CheckPasswordComplexity(password);
        EncryptFileWithHmac(inputFile, outputFile, password, versionToUse);
        var algorithm = versionToUse switch
        {
            V1_AES_ECB_HMAC_PBKDF2_10K => "AES-ECB with PBKDF2 (10k iterations)",
            V2_AES_CBC_HMAC_PBKDF2_100K => "AES-CBC with PBKDF2 (100k iterations)",
            V3_AES_CBC_HMAC_Argon2 => "AES-CBC with Argon2",
            V4_AES_GCM_Argon2 => "AES-GCM with Argon2 (AEAD)",
            _ => "Unknown"
        };
        Console.WriteLine($"File encrypted to {outputFile} using version {versionToUse} ({algorithm})");
    }
    else
    {
        var version = DecryptFileWithHmacVerification(inputFile, outputFile, password);
        var algorithm = version switch
        {
            V1_AES_ECB_HMAC_PBKDF2_10K => "AES-ECB with PBKDF2 (10k iterations)",
            V2_AES_CBC_HMAC_PBKDF2_100K => "AES-CBC with PBKDF2 (100k iterations)",
            V3_AES_CBC_HMAC_Argon2 => "AES-CBC with Argon2",
            V4_AES_GCM_Argon2 => "AES-GCM with Argon2 (AEAD)",
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
#endregion

#region Helper Methods
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
        V1_AES_ECB_HMAC_PBKDF2_10K => "AES-ECB with PBKDF2 (10k iterations)",
        V2_AES_CBC_HMAC_PBKDF2_100K => "AES-CBC with PBKDF2 (100k iterations)",
        V3_AES_CBC_HMAC_Argon2 => "AES-CBC with Argon2",
        V4_AES_GCM_Argon2 => "AES-GCM with Argon2 (AEAD)",
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
    
    if (version == V2_AES_CBC_HMAC_PBKDF2_100K || version == V3_AES_CBC_HMAC_Argon2)
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
    else if (version == V4_AES_GCM_Argon2)
    {
        if (fs.Length < 45)
        {
            Console.WriteLine("File too small to contain nonce");
            return;
        }
        
        var nonce = new byte[12];
        fs.ReadExactly(nonce);
        Console.WriteLine($"Nonce (12 bytes):");
        Console.WriteLine($"  {Convert.ToHexString(nonce)}");
        Console.WriteLine();
    }
    else if (version == V1_AES_ECB_HMAC_PBKDF2_10K)
    {
        Console.WriteLine("IV: Not used (ECB mode)");
        Console.WriteLine();
    }
    
    var currentPosition = fs.Position;
    var authTagSize = version == V4_AES_GCM_Argon2 ? 16 : 32;
    var authTagName = version == V4_AES_GCM_Argon2 ? "GCM Authentication Tag" : "HMAC-SHA256";
    var ciphertextLength = fs.Length - currentPosition - authTagSize;
    
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
    
    fs.Position = fs.Length - authTagSize;
    var authTag = new byte[authTagSize];
    fs.ReadExactly(authTag);
    Console.WriteLine($"{authTagName} ({authTagSize} bytes):");
    Console.WriteLine($"  {Convert.ToHexString(authTag)}");
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
          encrypt <inputFile> <outputFile> <password> <version> [-f|--force]  - Encrypt a file
          decrypt <inputFile> <outputFile> <password> [-f|--force]            - Decrypt a file
          dump <inputFile>                                                     - Dump encrypted file metadata

        Version options (required for encrypt):
          1 - AES-ECB with PBKDF2 10,000 iterations (legacy, least secure)
          2 - AES-CBC with PBKDF2 100,000 iterations (better)
          3 - AES-CBC with Argon2 64MB memory (good)
          4 - AES-GCM with Argon2 64MB memory (recommended, AEAD)

        Options:
          -f, --force  Overwrite output file without prompting
          -h, --help   Show this help message

        Examples:
          encrypt document.txt document.enc MyP@ssw0rd! 4
          encrypt document.txt document.enc MyP@ssw0rd! 4 --force
          decrypt document.enc document.txt MyP@ssw0rd!
          decrypt document.enc document.txt MyP@ssw0rd! -f
          dump document.enc
        """);
}
#endregion

#region Encryption Methods
void EncryptFileWithHmac(string inputFile, string outputFile, string password, byte version)
{
    using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
    using var fsEncrypted = new FileStream(outputFile, FileMode.Create, FileAccess.ReadWrite);

    fsEncrypted.WriteByte(version);

    switch (version)
    {
        case V1_AES_ECB_HMAC_PBKDF2_10K:
            EncryptFileWithHmacVersion1(fsInput, fsEncrypted, password);
            break;
        case V2_AES_CBC_HMAC_PBKDF2_100K:
            EncryptFileWithHmacVersion2(fsInput, fsEncrypted, password);
            break;
        case V3_AES_CBC_HMAC_Argon2:
            EncryptFileWithHmacVersion3(fsInput, fsEncrypted, password);
            break;
        case V4_AES_GCM_Argon2:
            EncryptFileWithGcmVersion4(fsInput, fsEncrypted, password);
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
    // Start from position 1 to exclude the version byte (it's written by the caller)
    fsEncrypted.Position = 1;
    var endOfCiphertext = fsEncrypted.Length;
    var buffer = new byte[endOfCiphertext - 1];
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
    // Start from position 1 to exclude the version byte (it's written by the caller)
    fsEncrypted.Position = 1;
    var endOfCiphertext = fsEncrypted.Length;
    var buffer = new byte[endOfCiphertext - 1];
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
    // Start from position 1 to exclude the version byte (it's written by the caller)
    fsEncrypted.Position = 1;
    var endOfCiphertext = fsEncrypted.Length;
    var buffer = new byte[endOfCiphertext - 1];
    fsEncrypted.ReadExactly(buffer);
    var tag = hmac.ComputeHash(buffer);
    fsEncrypted.Write(tag);
}

void EncryptFileWithGcmVersion4(FileStream fsInput, FileStream fsEncrypted, string password)
{
    var salt = RandomNumberGenerator.GetBytes(32);
    fsEncrypted.Write(salt);

    // Derive encryption key using Argon2
    var encryptionKey = new Argon2id(Encoding.UTF8.GetBytes(password))
    {
        Salt = salt,
        DegreeOfParallelism = 8,
        MemorySize = 65_536, // 64 MB
        Iterations = 4
    }.GetBytes(32);

    // GCM uses a 12-byte nonce (96 bits is optimal for GCM)
    var nonce = RandomNumberGenerator.GetBytes(12);
    fsEncrypted.Write(nonce);

    // Read plaintext into memory (GCM requires knowing the plaintext length upfront)
    var plaintext = new byte[fsInput.Length];
    fsInput.ReadExactly(plaintext);

    // Allocate buffer for ciphertext (same size as plaintext)
    var ciphertext = new byte[plaintext.Length];
    
    // GCM authentication tag (16 bytes / 128 bits)
    var tag = new byte[16];

    // Encrypt using AES-GCM
    using var aesGcm = new AesGcm(encryptionKey, 16);
    aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

    // Write ciphertext and tag
    fsEncrypted.Write(ciphertext);
    fsEncrypted.Write(tag);
}
#endregion

#region Decryption Methods
byte DecryptFileWithHmacVerification(string inputFile, string outputFile, string password)
{
    using var fsEncrypted = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
    using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);

    var version = fsEncrypted.ReadByte();

    switch ((byte)version)
    {
        case V1_AES_ECB_HMAC_PBKDF2_10K:
            DecryptFileWithHmacVerificationVersion1(fsEncrypted, fsOutput, password);
            return V1_AES_ECB_HMAC_PBKDF2_10K;
        case V2_AES_CBC_HMAC_PBKDF2_100K:
            DecryptFileWithHmacVerificationVersion2(fsEncrypted, fsOutput, password);
            return V2_AES_CBC_HMAC_PBKDF2_100K;
        case V3_AES_CBC_HMAC_Argon2:
            DecryptFileWithHmacVerificationVersion3(fsEncrypted, fsOutput, password);
            return V3_AES_CBC_HMAC_Argon2;
        case V4_AES_GCM_Argon2:
            DecryptFileWithGcmVersion4(fsEncrypted, fsOutput, password);
            return V4_AES_GCM_Argon2;
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
    // Start from position 1 to exclude the version byte (it was already read by the caller)
    fsEncrypted.Position = 1;
    var buffer = new byte[endOfCiphertext - 1];
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
    // Start from position 1 to exclude the version byte (it was already read by the caller)
    fsEncrypted.Position = 1;
    var buffer = new byte[endOfCiphertext - 1];
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
    // Start from position 1 to exclude the version byte (it was already read by the caller)
    fsEncrypted.Position = 1;
    var buffer = new byte[endOfCiphertext - 1];
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

void DecryptFileWithGcmVersion4(FileStream fsEncrypted, FileStream fsOutput, string password)
{
    var salt = new byte[32];
    fsEncrypted.ReadExactly(salt);

    var nonce = new byte[12];
    fsEncrypted.ReadExactly(nonce);

    // Derive encryption key using Argon2
    var encryptionKey = new Argon2id(Encoding.UTF8.GetBytes(password))
    {
        Salt = salt,
        DegreeOfParallelism = 8,
        MemorySize = 65_536, // 64 MB
        Iterations = 4
    }.GetBytes(32);

    var fileLength = fsEncrypted.Length;
    var tagSize = 16;
    if (fileLength < 1 + 32 + 12 + tagSize)
    {
        throw new InvalidOperationException("File too small to contain valid encrypted data");
    }

    // Calculate ciphertext length (total - version - salt - nonce - tag)
    var ciphertextLength = fileLength - 1 - 32 - 12 - tagSize;
    
    // Read ciphertext
    var ciphertext = new byte[ciphertextLength];
    fsEncrypted.ReadExactly(ciphertext);

    // Read authentication tag
    var tag = new byte[tagSize];
    fsEncrypted.ReadExactly(tag);

    // Allocate buffer for plaintext
    var plaintext = new byte[ciphertextLength];

    // Decrypt and verify using AES-GCM
    using var aesGcm = new AesGcm(encryptionKey, 16);
    try
    {
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
    }
    catch (CryptographicException)
    {
        throw new CryptographicException("Authentication failed - file may be corrupted, tampered with, or password is incorrect");
    }

    // Write decrypted plaintext
    fsOutput.Write(plaintext);
}
#endregion

#region Support Classes
// Wrapper stream that limits reading to a specific number of bytes,
// preventing reads beyond ciphertext boundaries during decryption
// The class is essential because during decryption, the CryptoStream
// needs to read only the encrypted data portion of the file (which ends before the HMAC tag).
// Without this limitation, the CryptoStream might try to decrypt
// the HMAC bytes as if they were part of the ciphertext, causing decryption errors
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
#endregion#endregion