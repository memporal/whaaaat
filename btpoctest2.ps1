<#
.SYNOPSIS
    Deep Audit for Granular WD/AD Permissions in PATH.
    Targets exactly what icacls revealed: WD (WriteData) and AD (AppendData).
#>

$RiskGroups = @("Everyone", "Users", "Authenticated Users", "BUILTIN\Users")

# Low-level flags that equate to "I can drop an EXE here"
$GranularFlags = @(
    [System.Security.AccessControl.FileSystemRights]::WriteData,
    [System.Text.RegularExpressions.Regex]::Escape("WriteData"),
    "CreateFiles",
    "AppendData"
)

$RawPath = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")
$AllPaths = $RawPath -split ";" | Where-Object { $_ -match "[a-zA-Z]:\\" } | Select-Object -Unique

Write-Host "[*] Auditing for Granular Write (WD/AD) Rights..." -ForegroundColor Cyan

foreach ($Dir in $AllPaths) {
    $Dir = $Dir.Trim()
    if (!(Test-Path $Dir)) { continue }

    try {
        $Acl = Get-Acl -Path $Dir
        foreach ($Access in $Acl.Access) {
            $Identity = $Access.IdentityReference.Value
            
            # Check if the identity is in our risk group
            if ($RiskGroups -contains $Identity -or $Identity -match "Users$|Everyone$") {
                
                $Rights = $Access.FileSystemRights.ToString()
                
                # Check for the specific WD/AD flags you found with icacls
                foreach ($Flag in $GranularFlags) {
                    if ($Rights -match $Flag) {
                        Write-Host "[!] HIJACKABLE: $Dir" -ForegroundColor Red
                        Write-Host "    - Identity: $Identity"
                        Write-Host "    - Granular Rights: $Rights"
                        break
                    }
                }
            }
        }
    } catch {
        Write-Host "[-] Access Denied: $Dir" -ForegroundColor Gray
    }
}
