# Check PowerShell version (requires PS 7+ for ExportPkcs8PrivateKey method)
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "PowerShell 7 or higher is required for this script. Current version: $($PSVersionTable.PSVersion)"
    Write-Host "Please install PowerShell 7+ from: https://github.com/PowerShell/PowerShell/releases"
    exit 1
}

Write-Host "PowerShell version $($PSVersionTable.PSVersion) detected - proceeding with PKCS#8 key generation..." -ForegroundColor Green

# Create RSA key
$rsa = [System.Security.Cryptography.RSA]::Create(2048)

# Export as PKCS#8
try {
    $privateKeyBytes = $rsa.ExportPkcs8PrivateKey()
    $privateKeyBase64 = [System.Convert]::ToBase64String($privateKeyBytes)
    
    # Create array of lines with proper 64-character wrapping
    $privateKeyLines = @("-----BEGIN PRIVATE KEY-----")
    for ($i = 0; $i -lt $privateKeyBase64.Length; $i += 64) {
        $lineLength = [Math]::Min(64, $privateKeyBase64.Length - $i)
        $privateKeyLines += $privateKeyBase64.Substring($i, $lineLength)
    }
    $privateKeyLines += "-----END PRIVATE KEY-----"
    
    Write-Host "Successfully generated PKCS#8 private key" -ForegroundColor Green
}
catch {
    Write-Error "Failed to generate PKCS#8 private key: $($_.Exception.Message)"
    Write-Host "Please ensure you're using PowerShell 7+ with .NET 5.0 or higher" -ForegroundColor Yellow
    exit 1
}

# Export public key for reference
try {
    $publicKeyBytes = $rsa.ExportSubjectPublicKeyInfo()
    $publicKeyBase64 = [System.Convert]::ToBase64String($publicKeyBytes)
    
    # Create array of lines with proper 64-character wrapping
    $publicKeyLines = @("-----BEGIN PUBLIC KEY-----")
    for ($i = 0; $i -lt $publicKeyBase64.Length; $i += 64) {
        $lineLength = [Math]::Min(64, $publicKeyBase64.Length - $i)
        $publicKeyLines += $publicKeyBase64.Substring($i, $lineLength)
    }
    $publicKeyLines += "-----END PUBLIC KEY-----"
}
catch {
    Write-Warning "Could not export public key: $($_.Exception.Message)"
    $publicKeyLines = $null
}

# Save private key using Out-File with Unix line endings
$privateKeyContent = ($privateKeyLines -join "`n") + "`n"
$privateKeyContent | Out-File -FilePath "snowflake_private_key.pem" -Encoding UTF8NoBOM -NoNewline

# Save public key if available
if ($publicKeyLines) {
    $publicKeyContent = ($publicKeyLines -join "`n") + "`n"
    $publicKeyContent | Out-File -FilePath "snowflake_public_key.pem" -Encoding UTF8NoBOM -NoNewline
    Write-Host "Keys saved:" -ForegroundColor Cyan
    Write-Host "  Private key: snowflake_private_key.pem (PKCS#8 format)" -ForegroundColor White
    Write-Host "  Public key:  snowflake_public_key.pem" -ForegroundColor White
}
else {
    Write-Host "Private key saved: snowflake_private_key.pem (PKCS#8 format)" -ForegroundColor Cyan
}

# Clean up
$rsa.Dispose()

Write-Host "`nKey generation complete!" -ForegroundColor Green