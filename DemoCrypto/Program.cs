using System.Security.Cryptography;

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
        EncryptFile(inputFile, outputFile, password);
        Console.WriteLine($"✓ File encrypted to {outputFile}");
    }
    else
    {
        DecryptFile(inputFile, outputFile, password);
        Console.WriteLine($"✓ File decrypted to {outputFile}");
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
          encrypt <inputFile> <outputFile> <password>  - Encrypt a file
          decrypt <inputFile> <outputFile> <password>  - Decrypt a file

        Examples:
          encrypt document.txt document.enc MyP@ssw0rd!
          decrypt document.enc document.txt MyP@ssw0rd!

        Options:
          -h, --help  Show this help message
        """);
}

void EncryptFile(string inputFile, string outputFile, string password)
{
    var salt = GenerateRandomBytes(32);
    using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
    using var fsEncrypted = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
    
    fsEncrypted.Write(salt, 0, salt.Length);

    using var aes = Aes.Create();
    using var key = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
    aes.Key = key.GetBytes(32);
    aes.IV = GenerateRandomBytes(16);
    fsEncrypted.Write(aes.IV, 0, aes.IV.Length);

    using var cs = new CryptoStream(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write);
    fsInput.CopyTo(cs);
}

void DecryptFile(string inputFile, string outputFile, string password)
{
    using var fsEncrypted = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
    using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
    
    var salt = new byte[32];
    var bytesRead = fsEncrypted.Read(salt, 0, salt.Length);
    if (bytesRead != salt.Length)
    {
        throw new InvalidOperationException("Invalid encrypted file format: missing salt");
    }

    var iv = new byte[16];
    bytesRead = fsEncrypted.Read(iv, 0, iv.Length);
    if (bytesRead != iv.Length)
    {
        throw new InvalidOperationException("Invalid encrypted file format: missing IV");
    }

    using var aes = Aes.Create();
    using var key = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
    aes.Key = key.GetBytes(32);
    aes.IV = iv;

    using var cs = new CryptoStream(fsEncrypted, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fsOutput);
}

byte[] GenerateRandomBytes(int count)
{
    var bytes = new byte[count];
    RandomNumberGenerator.Fill(bytes);
    return bytes;
}
