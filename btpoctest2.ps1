<#
.SYNOPSIS
    Audit system and user PATH variables for insecure (writable) directories.
    Targeted for Privilege Escalation (PrivEsc) analysis.
#>

# Define high-risk identity groups to check for
$RiskGroups = @("Everyone", "Users", "Authenticated Users", "BUILTIN\Users")

# Define write-related permissions
$WritePermissions = @("Write", "Modify", "FullControl", "WriteData", "CreateFiles")

Write-Host "[*] Beginning Machine-wide PATH Hijack Audit..." -ForegroundColor Cyan
Write-Host "----------------------------------------------------"

# 1. Collect all unique paths from System and User environments
$RawPath = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")
$AllPaths = $RawPath -split ";" | Where-Object { $_ -ne "" } | Select-Object -Unique

$VulnerablePaths = @()

# 2. Iterate and analyze each directory
foreach ($Path in $AllPaths) {
    if (!(Test-Path $Path)) {
        Write-Host "[!] Path does not exist but is in PATH: $Path" -ForegroundColor Yellow
        continue
    }

    try {
        $ACL = Get-Acl -Path $Path
        $AccessRules = $ACL.Access | Where-Object { $_.IdentityReference -in $RiskGroups }

        foreach ($Rule in $AccessRules) {
            # Check if any of the permissions match our 'Write' list
            foreach ($Perm in $WritePermissions) {
                if ($Rule.FileSystemRights.ToString() -match $Perm) {
                    Write-Host "[!] VULNERABLE: $Path" -ForegroundColor Red
                    Write-Host "    - Group: $($Rule.IdentityReference)"
                    Write-Host "    - Rights: $($Rule.FileSystemRights)"
                    
                    $VulnerablePaths += [PSCustomObject]@{
                        Path   = $Path
                        Group  = $Rule.IdentityReference
                        Rights = $Rule.FileSystemRights
                    }
                    break 
                }
            }
        }
    } catch {
        Write-Host "[-] Access Denied checking ACL for: $Path" -ForegroundColor Gray
    }
}

# 3. Summary Report
Write-Host "`n----------------------------------------------------"
if ($VulnerablePaths.Count -gt 0) {
    Write-Host "[+] Found $($VulnerablePaths.Count) potential hijack points." -ForegroundColor Red
} else {
    Write-Host "[+] No insecure PATH directories identified." -ForegroundColor Green
}
