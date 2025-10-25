# Test-Encryption.ps1
# Comprehensive test suite for DemoCrypto encryption utility
# Requires PowerShell 7.0 or later

#Requires -Version 7.0

param(
    [string]$ExePath = ".\DemoCrypto\bin\Release\net10.0\DemoCrypto.exe"
)

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "ERROR: This script requires PowerShell 7.0 or later." -ForegroundColor Red
    Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host "`nPlease install PowerShell 7 from: https://aka.ms/powershell" -ForegroundColor Cyan
    exit 1
}

Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Green

# Test configuration
$TestDir = ".\TestFiles"
$TestPassword = "TestP@ssw0rd123!"
$WrongPassword = "WrongP@ssw0rd!"

# Colors for output
$ColorPass = "Green"
$ColorFail = "Red"
$ColorInfo = "Cyan"
$ColorWarn = "Yellow"

# Test statistics
$script:TotalTests = 0
$script:PassedTests = 0
$script:FailedTests = 0
$script:TestResults = @()

# Initialize test environment
function Initialize-TestEnvironment {
    Write-Host "`n=== Initializing Test Environment ===" -ForegroundColor $ColorInfo
    
    # Check if executable exists
    if (-not (Test-Path $ExePath)) {
        # Try to build the project
        Write-Host "Executable not found. Attempting to build..." -ForegroundColor $ColorWarn
        Push-Location ".\DemoCrypto"
        dotnet build -c Release
        Pop-Location
        
        if (-not (Test-Path $ExePath)) {
            Write-Host "ERROR: Could not find or build executable at: $ExePath" -ForegroundColor $ColorFail
            exit 1
        }
    }
    
    Write-Host "Using executable: $ExePath" -ForegroundColor $ColorInfo
    
    # Create test directory
    if (Test-Path $TestDir) {
        Remove-Item -Path $TestDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $TestDir | Out-Null
    Write-Host "Created test directory: $TestDir" -ForegroundColor $ColorInfo
    
    # Create test files of various sizes
    Create-TestFiles
}

# Create test files
function Create-TestFiles {
    Write-Host "`nCreating test files..." -ForegroundColor $ColorInfo
    
    # Empty file
    New-Item -ItemType File -Path "$TestDir\empty.txt" | Out-Null
    
    # Small file (< 16 bytes - less than one AES block)
    "Hello" | Out-File -FilePath "$TestDir\small.txt" -NoNewline
    
    # Medium file (exactly 16 bytes - one AES block)
    "0123456789ABCDEF" | Out-File -FilePath "$TestDir\medium.txt" -NoNewline
    
    # Large file (~1KB with various characters)
    $largeContent = "The quick brown fox jumps over the lazy dog. " * 25
    $largeContent | Out-File -FilePath "$TestDir\large.txt" -NoNewline
    
    # Binary-like file with special characters
    $binaryContent = -join ((0..255) | ForEach-Object { [char]$_ })
    $binaryContent | Out-File -FilePath "$TestDir\binary.txt" -NoNewline
    
    Write-Host "Created test files: empty, small, medium, large, binary" -ForegroundColor $ColorInfo
}

# Test helper function
function Test-Case {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [bool]$ShouldSucceed = $true
    )
    
    $script:TotalTests++
    Write-Host "`n[$script:TotalTests] Testing: $Name" -ForegroundColor $ColorInfo
    
    try {
        $result = & $Test
        $success = $LASTEXITCODE -eq 0
        
        if ($success -eq $ShouldSucceed) {
            Write-Host "  ✓ PASS" -ForegroundColor $ColorPass
            $script:PassedTests++
            $script:TestResults += [PSCustomObject]@{
                TestNumber = $script:TotalTests
                Name = $Name
                Result = "PASS"
                Expected = $ShouldSucceed ? "Success" : "Failure"
                Actual = $success ? "Success" : "Failure"
            }
        }
        else {
            Write-Host "  ✗ FAIL - Expected $($ShouldSucceed ? 'success' : 'failure') but got $($success ? 'success' : 'failure')" -ForegroundColor $ColorFail
            $script:FailedTests++
            $script:TestResults += [PSCustomObject]@{
                TestNumber = $script:TotalTests
                Name = $Name
                Result = "FAIL"
                Expected = $ShouldSucceed ? "Success" : "Failure"
                Actual = $success ? "Success" : "Failure"
            }
        }
    }
    catch {
        Write-Host "  ✗ FAIL - Exception: $_" -ForegroundColor $ColorFail
        $script:FailedTests++
        $script:TestResults += [PSCustomObject]@{
            TestNumber = $script:TotalTests
            Name = $Name
            Result = "FAIL"
            Expected = $ShouldSucceed ? "Success" : "Failure"
            Actual = "Exception: $_"
        }
    }
}

# Run executable
function Invoke-Crypto {
    param(
        [string[]]$Arguments
    )
    
    $output = & $ExePath $Arguments 2>&1
    Write-Host "  Command: $ExePath $($Arguments -join ' ')" -ForegroundColor Gray
    Write-Host "  Exit Code: $LASTEXITCODE" -ForegroundColor Gray
    if ($output) {
        Write-Host "  Output: $($output -join "`n  ")" -ForegroundColor Gray
    }
    return $output
}

# Test Version 1 (AES-ECB with PBKDF2 10k)
function Test-Version1 {
    Write-Host "`n`n=== Testing Version 1 (AES-ECB/PBKDF2-10k) ===" -ForegroundColor $ColorInfo
    
    Test-Case "V1: Encrypt and decrypt small file" {
        Invoke-Crypto @("encrypt", "$TestDir\small.txt", "$TestDir\small_v1.enc", $TestPassword, "1")
        Invoke-Crypto @("decrypt", "$TestDir\small_v1.enc", "$TestDir\small_v1_dec.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\small.txt" -Raw) (Get-Content "$TestDir\small_v1_dec.txt" -Raw)
        if ($diff) { throw "Decrypted content doesn't match original" }
    }
    
    Test-Case "V1: Encrypt and decrypt large file" {
        Invoke-Crypto @("encrypt", "$TestDir\large.txt", "$TestDir\large_v1.enc", $TestPassword, "1")
        Invoke-Crypto @("decrypt", "$TestDir\large_v1.enc", "$TestDir\large_v1_dec.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\large.txt" -Raw) (Get-Content "$TestDir\large_v1_dec.txt" -Raw)
        if ($diff) { throw "Decrypted content doesn't match original" }
    }
    
    Test-Case "V1: Dump encrypted file metadata" {
        Invoke-Crypto @("dump", "$TestDir\small_v1.enc")
    }
}

# Test Version 2 (AES-CBC with PBKDF2 100k)
function Test-Version2 {
    Write-Host "`n`n=== Testing Version 2 (AES-CBC/PBKDF2-100k) ===" -ForegroundColor $ColorInfo
    
    Test-Case "V2: Encrypt and decrypt small file" {
        Invoke-Crypto @("encrypt", "$TestDir\small.txt", "$TestDir\small_v2.enc", $TestPassword, "2")
        Invoke-Crypto @("decrypt", "$TestDir\small_v2.enc", "$TestDir\small_v2_dec.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\small.txt" -Raw) (Get-Content "$TestDir\small_v2_dec.txt" -Raw)
        if ($diff) { throw "Decrypted content doesn't match original" }
    }
    
    Test-Case "V2: Encrypt and decrypt medium file" {
        Invoke-Crypto @("encrypt", "$TestDir\medium.txt", "$TestDir\medium_v2.enc", $TestPassword, "2")
        Invoke-Crypto @("decrypt", "$TestDir\medium_v2.enc", "$TestDir\medium_v2_dec.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\medium.txt" -Raw) (Get-Content "$TestDir\medium_v2_dec.txt" -Raw)
        if ($diff) { throw "Decrypted content doesn't match original" }
    }
    
    Test-Case "V2: Dump encrypted file metadata" {
        Invoke-Crypto @("dump", "$TestDir\small_v2.enc")
    }
}

# Test Version 3 (AES-CBC with Argon2)
function Test-Version3 {
    Write-Host "`n`n=== Testing Version 3 (AES-CBC/Argon2) ===" -ForegroundColor $ColorInfo
    
    Test-Case "V3: Encrypt and decrypt small file" {
        Invoke-Crypto @("encrypt", "$TestDir\small.txt", "$TestDir\small_v3.enc", $TestPassword, "3")
        Invoke-Crypto @("decrypt", "$TestDir\small_v3.enc", "$TestDir\small_v3_dec.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\small.txt" -Raw) (Get-Content "$TestDir\small_v3_dec.txt" -Raw)
        if ($diff) { throw "Decrypted content doesn't match original" }
    }
    
    Test-Case "V3: Encrypt and decrypt binary file" {
        Invoke-Crypto @("encrypt", "$TestDir\binary.txt", "$TestDir\binary_v3.enc", $TestPassword, "3")
        Invoke-Crypto @("decrypt", "$TestDir\binary_v3.enc", "$TestDir\binary_v3_dec.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\binary.txt" -Raw) (Get-Content "$TestDir\binary_v3_dec.txt" -Raw)
        if ($diff) { throw "Decrypted content doesn't match original" }
    }
    
    Test-Case "V3: Dump encrypted file metadata" {
        Invoke-Crypto @("dump", "$TestDir\small_v3.enc")
    }
}

# Test Version 4 (AES-GCM with Argon2) - Default
function Test-Version4 {
    Write-Host "`n`n=== Testing Version 4 (AES-GCM/Argon2 - Default) ===" -ForegroundColor $ColorInfo
    
    Test-Case "V4: Encrypt and decrypt with explicit version" {
        Invoke-Crypto @("encrypt", "$TestDir\small.txt", "$TestDir\small_v4.enc", $TestPassword, "4")
        Invoke-Crypto @("decrypt", "$TestDir\small_v4.enc", "$TestDir\small_v4_dec.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\small.txt" -Raw) (Get-Content "$TestDir\small_v4_dec.txt" -Raw)
        if ($diff) { throw "Decrypted content doesn't match original" }
    }
    
    Test-Case "V4: Encrypt with default version (should be V4)" {
        Invoke-Crypto @("encrypt", "$TestDir\large.txt", "$TestDir\large_default.enc", $TestPassword)
        Invoke-Crypto @("decrypt", "$TestDir\large_default.enc", "$TestDir\large_default_dec.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\large.txt" -Raw) (Get-Content "$TestDir\large_default_dec.txt" -Raw)
        if ($diff) { throw "Decrypted content doesn't match original" }
    }
    
    Test-Case "V4: Verify default is V4 via dump" {
        $output = Invoke-Crypto @("dump", "$TestDir\large_default.enc")
        $versionLine = $output | Where-Object { $_ -like "*Version:*4*" }
        if (-not $versionLine) { throw "Default version is not V4" }
    }
    
    Test-Case "V4: Dump encrypted file metadata" {
        Invoke-Crypto @("dump", "$TestDir\small_v4.enc")
    }
}

# Test edge cases that should fail
function Test-FailureCases {
    Write-Host "`n`n=== Testing Failure Cases (Should Fail) ===" -ForegroundColor $ColorInfo
    
    Test-Case "FAIL: Wrong password on V1" {
        Invoke-Crypto @("decrypt", "$TestDir\small_v1.enc", "$TestDir\fail_test.txt", $WrongPassword)
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Wrong password on V2" {
        Invoke-Crypto @("decrypt", "$TestDir\small_v2.enc", "$TestDir\fail_test.txt", $WrongPassword)
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Wrong password on V3" {
        Invoke-Crypto @("decrypt", "$TestDir\small_v3.enc", "$TestDir\fail_test.txt", $WrongPassword)
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Wrong password on V4" {
        Invoke-Crypto @("decrypt", "$TestDir\small_v4.enc", "$TestDir\fail_test.txt", $WrongPassword)
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Non-existent input file" {
        Invoke-Crypto @("encrypt", "$TestDir\nonexistent.txt", "$TestDir\output.enc", $TestPassword)
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Invalid version number" {
        Invoke-Crypto @("encrypt", "$TestDir\small.txt", "$TestDir\output.enc", $TestPassword, "99")
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Decrypt non-encrypted file" {
        Invoke-Crypto @("decrypt", "$TestDir\small.txt", "$TestDir\fail_test.txt", $TestPassword)
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Dump non-encrypted file" {
        Invoke-Crypto @("dump", "$TestDir\small.txt")
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Empty file encryption (should work but test handling)" {
        Invoke-Crypto @("encrypt", "$TestDir\empty.txt", "$TestDir\empty.enc", $TestPassword)
        Invoke-Crypto @("decrypt", "$TestDir\empty.enc", "$TestDir\empty_dec.txt", $TestPassword)
        # This should actually succeed, so we expect success
    } -ShouldSucceed $true
    
    Test-Case "FAIL: Insufficient arguments" {
        Invoke-Crypto @("encrypt", "$TestDir\small.txt")
    } -ShouldSucceed $false
    
    Test-Case "FAIL: Unknown command" {
        Invoke-Crypto @("invalid", "$TestDir\small.txt", "$TestDir\output.enc", $TestPassword)
    } -ShouldSucceed $false
}

# Test file tampering detection
function Test-Tampering {
    Write-Host "`n`n=== Testing Tampering Detection ===" -ForegroundColor $ColorInfo
    
    # Create a test file and encrypt it
    "Tampering test content" | Out-File -FilePath "$TestDir\tamper.txt" -NoNewline
    Invoke-Crypto @("encrypt", "$TestDir\tamper.txt", "$TestDir\tamper_v2.enc", $TestPassword, "2") | Out-Null
    Invoke-Crypto @("encrypt", "$TestDir\tamper.txt", "$TestDir\tamper_v4.enc", $TestPassword, "4") | Out-Null
    
    Test-Case "TAMPER: Detect modified ciphertext (V2)" {
        # Copy file and modify a byte in the middle
        Copy-Item "$TestDir\tamper_v2.enc" "$TestDir\tamper_v2_modified.enc"
        $bytes = [System.IO.File]::ReadAllBytes("$TestDir\tamper_v2_modified.enc")
        $bytes[50] = ($bytes[50] + 1) % 256  # Modify one byte
        [System.IO.File]::WriteAllBytes("$TestDir\tamper_v2_modified.enc", $bytes)
        
        Invoke-Crypto @("decrypt", "$TestDir\tamper_v2_modified.enc", "$TestDir\fail_test.txt", $TestPassword)
    } -ShouldSucceed $false
    
    Test-Case "TAMPER: Detect modified ciphertext (V4)" {
        # Copy file and modify a byte in the middle
        Copy-Item "$TestDir\tamper_v4.enc" "$TestDir\tamper_v4_modified.enc"
        $bytes = [System.IO.File]::ReadAllBytes("$TestDir\tamper_v4_modified.enc")
        $bytes[50] = ($bytes[50] + 1) % 256  # Modify one byte
        [System.IO.File]::WriteAllBytes("$TestDir\tamper_v4_modified.enc", $bytes)
        
        Invoke-Crypto @("decrypt", "$TestDir\tamper_v4_modified.enc", "$TestDir\fail_test.txt", $TestPassword)
    } -ShouldSucceed $false
    
    Test-Case "TAMPER: Detect truncated file" {
        Copy-Item "$TestDir\tamper_v2.enc" "$TestDir\tamper_v2_truncated.enc"
        $bytes = [System.IO.File]::ReadAllBytes("$TestDir\tamper_v2_truncated.enc")
        $truncated = $bytes[0..($bytes.Length - 10)]  # Remove last 10 bytes
        [System.IO.File]::WriteAllBytes("$TestDir\tamper_v2_truncated.enc", $truncated)
        
        Invoke-Crypto @("decrypt", "$TestDir\tamper_v2_truncated.enc", "$TestDir\fail_test.txt", $TestPassword)
    } -ShouldSucceed $false
}

# Test help and usage
function Test-HelpAndUsage {
    Write-Host "`n`n=== Testing Help and Usage ===" -ForegroundColor $ColorInfo
    
    Test-Case "HELP: Show help with -h" {
        Invoke-Crypto @("-h")
    }
    
    Test-Case "HELP: Show help with --help" {
        Invoke-Crypto @("--help")
    }
    
    Test-Case "HELP: Show help with no arguments" {
        Invoke-Crypto @()
    }
}

# Test cross-version compatibility
function Test-CrossVersion {
    Write-Host "`n`n=== Testing Cross-Version Compatibility ===" -ForegroundColor $ColorInfo
    
    Test-Case "COMPAT: V1 file can be decrypted correctly" {
        Invoke-Crypto @("decrypt", "$TestDir\small_v1.enc", "$TestDir\compat_v1.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\small.txt" -Raw) (Get-Content "$TestDir\compat_v1.txt" -Raw)
        if ($diff) { throw "Content mismatch" }
    }
    
    Test-Case "COMPAT: V2 file can be decrypted correctly" {
        Invoke-Crypto @("decrypt", "$TestDir\small_v2.enc", "$TestDir\compat_v2.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\small.txt" -Raw) (Get-Content "$TestDir\compat_v2.txt" -Raw)
        if ($diff) { throw "Content mismatch" }
    }
    
    Test-Case "COMPAT: V3 file can be decrypted correctly" {
        Invoke-Crypto @("decrypt", "$TestDir\small_v3.enc", "$TestDir\compat_v3.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\small.txt" -Raw) (Get-Content "$TestDir\compat_v3.txt" -Raw)
        if ($diff) { throw "Content mismatch" }
    }
    
    Test-Case "COMPAT: V4 file can be decrypted correctly" {
        Invoke-Crypto @("decrypt", "$TestDir\small_v4.enc", "$TestDir\compat_v4.txt", $TestPassword)
        $diff = Compare-Object (Get-Content "$TestDir\small.txt" -Raw) (Get-Content "$TestDir\compat_v4.txt" -Raw)
        if ($diff) { throw "Content mismatch" }
    }
}

# Generate test report
function Show-TestReport {
    Write-Host "`n`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorInfo
    Write-Host "║              TEST EXECUTION SUMMARY                        ║" -ForegroundColor $ColorInfo
    Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor $ColorInfo
    Write-Host "║ Total Tests:  $($script:TotalTests.ToString().PadLeft(3))                                         ║" -ForegroundColor $ColorInfo
    Write-Host "║ Passed:       " -NoNewline -ForegroundColor $ColorInfo
    Write-Host "$($script:PassedTests.ToString().PadLeft(3))" -NoNewline -ForegroundColor $ColorPass
    Write-Host "                                         ║" -ForegroundColor $ColorInfo
    Write-Host "║ Failed:       " -NoNewline -ForegroundColor $ColorInfo
    Write-Host "$($script:FailedTests.ToString().PadLeft(3))" -NoNewline -ForegroundColor $ColorFail
    Write-Host "                                         ║" -ForegroundColor $ColorInfo
    
    $successRate = $script:TotalTests -gt 0 ? [math]::Round(($script:PassedTests / $script:TotalTests) * 100, 2) : 0
    
    Write-Host "║ Success Rate: " -NoNewline -ForegroundColor $ColorInfo
    $rateColor = $successRate -eq 100 ? $ColorPass : ($successRate -ge 80 ? $ColorWarn : $ColorFail)
    Write-Host "$($successRate.ToString('0.00').PadLeft(6))%" -NoNewline -ForegroundColor $rateColor
    Write-Host "                                    ║" -ForegroundColor $ColorInfo
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor $ColorInfo
    
    if ($script:FailedTests -gt 0) {
        Write-Host "`nFailed Tests:" -ForegroundColor $ColorFail
        $script:TestResults | Where-Object { $_.Result -eq "FAIL" } | ForEach-Object {
            Write-Host "  [$($_.TestNumber)] $($_.Name)" -ForegroundColor $ColorFail
            Write-Host "      Expected: $($_.Expected), Actual: $($_.Actual)" -ForegroundColor Gray
        }
    }
    
    # Export detailed results to CSV
    $reportPath = "$TestDir\TestReport.csv"
    $script:TestResults | Export-Csv -Path $reportPath -NoTypeInformation
    Write-Host "`nDetailed test report saved to: $reportPath" -ForegroundColor $ColorInfo
}

# Main execution
function Main {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorInfo
    Write-Host "║         DemoCrypto Comprehensive Test Suite               ║" -ForegroundColor $ColorInfo
    Write-Host "║         Testing Cryptographic Agility                      ║" -ForegroundColor $ColorInfo
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor $ColorInfo
    
    Initialize-TestEnvironment
    
    # Run all test suites
    Test-Version1
    Test-Version2
    Test-Version3
    Test-Version4
    Test-FailureCases
    Test-Tampering
    Test-HelpAndUsage
    Test-CrossVersion
    
    $stopwatch.Stop()
    
    Show-TestReport
    
    Write-Host "`nTotal execution time: $($stopwatch.Elapsed.TotalSeconds.ToString('0.00')) seconds" -ForegroundColor $ColorInfo
    
    # Return exit code based on test results
    if ($script:FailedTests -eq 0) {
        Write-Host "`n✓ All tests passed!" -ForegroundColor $ColorPass
        exit 0
    }
    else {
        Write-Host "`n✗ Some tests failed!" -ForegroundColor $ColorFail
        exit 1
    }
}

# Run the tests
Main
