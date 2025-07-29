# ==========================================
#  Block Non-RFC Compliant HTTP Traffic – 30-case regression pack
#  Author: Tsvetomir
#  Date  : 20.04.2025
# ==========================================

$TargetHost   = "perdu.com"           # httpbin.org is also amazing for tests
$Port         = 80
$TimeoutMs    = 5000                  # used for connect, read and overall limits

function Send-RawHttpRequest {
    [CmdletBinding()]
    param(
        [string]$TargetHost,
        [int]   $Port      = 80,
        [string]$Request,
        [int]   $Timeout   = 5000      # milliseconds
    )

    try {
        # ── TCP connect ───────────────────────────────────────────────
        $client = [System.Net.Sockets.TcpClient]::new()
        $async  = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($Timeout, $false)) {
            throw "Connect timeout after $Timeout ms"
        }
        $client.EndConnect($async)

        # ── send request ──────────────────────────────────────────────
        $stream            = $client.GetStream()
        $stream.ReadTimeout = $Timeout               # applies to every read
        $writer            = [System.IO.StreamWriter]::new($stream)
        $writer.NewLine    = "`r`n"
        $writer.AutoFlush  = $true
        $writer.Write($Request)

        # ── read reply with timeout-aware loop ───────────────────────
        $reader = [System.IO.StreamReader]::new($stream)
        $buffer = New-Object System.Text.StringBuilder
        try {
            while ($true) {
                $char = $reader.Read()       # throws after ReadTimeout
                if ($char -eq -1) { break }  # remote closed cleanly
                [void]$buffer.Append([char]$char)
            }
        }
        catch [System.IO.IOException] {
            # timeout or other read error – we accept what we got
        }

        $client.Close()
        return $buffer.ToString()
    }
    catch {
        return "[ERROR] $_"
    }
}

function Invoke-TestSuite {
    param(
        [array] $TestCases,
        [string] $LogPath = ".\HttpMalformedTest-log.csv"
    )

    # ensure log directory exists
    $dir = Split-Path $LogPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }

    foreach ($t in $TestCases) {
        Write-Host "▶ $($t.Name)"
        $resp   = Send-RawHttpRequest -TargetHost $TargetHost -Port $Port `
                                      -Request $t.Request  -Timeout $TimeoutMs
        $first  = ($resp -split "`n")[0].Trim()

        [pscustomobject]@{
            Timestamp = (Get-Date).ToString("s")
            Host      = $TargetHost
            Test      = $t.Name
            Expected  = $t.Expect
            FirstLine = $first
            FullResp  = $resp.Replace("`r","␍").Replace("`n","␊")
        } | Export-Csv -Path $LogPath -Append -NoTypeInformation -Encoding UTF8
    }
}

# ───────────────────────────────────────────
# ░ Test Batch 1 – Baseline & vendor repro (8 cases)
# ───────────────────────────────────────────
$TestBatch1 = @(
    @{ Name = "1-A  Valid GET";                      Expect="200/301/302";          Request = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n" }
    @{ Name = "1-B  Invalid HTTP version 0.9";       Expect="Blocked";              Request = "GET / HTTP/0.9`r`nHost: $TargetHost`r`n`r`n" }
    @{ Name = "1-C  Invalid method GRT";             Expect="Blocked";              Request = "GRT / HTTP/1.1`r`nHost: $TargetHost`r`n`r`n" }
    @{ Name = "1-D  Host header empty value";        Expect="<not blocked per Zscaler>"; Request = "GET / HTTP/1.1`r`nHost: `r`nConnection: close`r`n`r`n" }
    @{ Name = "1-E  GET with body";                  Expect="Should be allowed";    Request = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nContent-Length: 17`r`nConnection: close`r`n`r`nThisShouldNotBeHere" }
    @{ Name = "1-F  Invalid User-Agent string";      Expect="Should be allowed";    Request = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nUser-Agent: InvalidUserAgent/1.0`r`nConnection: close`r`n`r`n" }
    @{ Name = "1-G  Empty User-Agent";               Expect="Should be allowed";    Request = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nUser-Agent: `r`nConnection: close`r`n`r`n" }
    @{ Name = "1-H  Empty header name (: value)";    Expect="Blocked";              Request = "GET / HTTP/1.1`r`nHost: $TargetHost`r`n: InvalidHeaderValue`r`nConnection: close`r`n`r`n" }
)

# ───────────────────────────────────────────
# ░ Test Batch 2 – Host-header edge cases (7 cases)
# ───────────────────────────────────────────
$TestBatch2 = @(
    @{ Name = "2-A  Missing Host header";            Expect="Blocked";              Request = "GET / HTTP/1.1`r`nUser-Agent: test`r`nConnection: close`r`n`r`n" }
    @{ Name = "2-B  Duplicate Host headers";         Expect="Blocked";              Request = "GET / HTTP/1.1`r`nHost: foo.com`r`nHost: bar.com`r`nConnection: close`r`n`r`n" }
    @{ Name = "2-C  Over-long Host header (9 KB)";   Expect="Blocked";              Request = "GET / HTTP/1.1`r`nHost: " + ("A"*9216) + "`r`nConnection: close`r`n`r`n" }
    @{ Name = "2-D  Host with bad chars";            Expect="Blocked";              Request = "GET / HTTP/1.1`r`nHost: bad`u0000host`r`nConnection: close`r`n`r`n" }
    @{ Name = "2-E  Host line-folding (obs-fold)";   Expect="Blocked";              Request = "GET / HTTP/1.1`r`nHost:`r`n bar.com`r`nConnection: close`r`n`r`n" }
    @{ Name = "2-F  Absolute-URI in GET (proxy)";    Expect="Allowed";              Request = "GET http://$TargetHost/ HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n" }
    @{ Name = "2-G  IPv6 literal Host";              Expect="Allowed";              Request = "GET / HTTP/1.1`r`nHost: [2001:db8::1]`r`nConnection: close`r`n`r`n" }
)

# ───────────────────────────────────────────
# ░ Test Batch 3 – TE / CL request-smuggling probes (7 cases)
# ───────────────────────────────────────────
$chunk = "4`r`nWiki`r`n5`r`npedia`r`n0`r`n`r`n"
$TestBatch3 = @(
    @{ Name = "3-A  Valid chunked";                  Expect="Allowed";              Request = "POST / HTTP/1.1`r`nHost: $TargetHost`r`nTransfer-Encoding: chunked`r`nConnection: close`r`n`r`n$chunk" }
    @{ Name = "3-B  Chunked missing final 0-chunk";  Expect="Blocked";              Request = "POST / HTTP/1.1`r`nHost: $TargetHost`r`nTransfer-Encoding: chunked`r`nConnection: close`r`n`r`n4`r`nWiki`r`n" }
    @{ Name = "3-C  Content-Length & TE (CL.TE)";    Expect="Blocked";              Request = "POST / HTTP/1.1`r`nHost: $TargetHost`r`nContent-Length: 5`r`nTransfer-Encoding: chunked`r`nConnection: close`r`n`r`n$chunk" }
    @{ Name = "3-D  TE before CL (TE.CL)";           Expect="Blocked";              Request = "POST / HTTP/1.1`r`nHost: $TargetHost`r`nTransfer-Encoding: chunked`r`nContent-Length: 5`r`nConnection: close`r`n`r`n$chunk" }
    @{ Name = "3-E  Content-Length too small";       Expect="Blocked";              Request = "POST / HTTP/1.1`r`nHost: $TargetHost`r`nContent-Length: 3`r`nConnection: close`r`n`r`n12345" }
    @{ Name = "3-F  Content-Length zero on POST";    Expect="Allowed";              Request = "POST / HTTP/1.1`r`nHost: $TargetHost`r`nContent-Length: 0`r`nConnection: close`r`n`r`n" }
    @{ Name = "3-G  Transfer-Encoding: gzip";        Expect="Blocked";              Request = "POST / HTTP/1.1`r`nHost: $TargetHost`r`nTransfer-Encoding: gzip`r`nContent-Length: 3`r`nConnection: close`r`n`r`nXYZ" }
)

# ───────────────────────────────────────────
# ░ Test Batch 4 – Exotic tokens & line format (8 cases)
# ───────────────────────────────────────────
$TestBatch4 = @(
    @{ Name = "4-A  Lone LF delimiters";             Expect="Blocked";              Request = "GET / HTTP/1.1`nHost: $TargetHost`nConnection: close`n`n" }
    @{ Name = "4-B  Start line > 8 KB";              Expect="Blocked";              Request = "GET /" + ("a"*9000) + " HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n" }
    @{ Name = "4-C  Header name with space";         Expect="Blocked";              Request = "GET / HTTP/1.1`r`nHo st: foo`r`nConnection: close`r`n`r`n" }
    @{ Name = "4-D  Non-ASCII method (ÜGET)";        Expect="Blocked";              Request = "ÜGET / HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n" }
    @{ Name = "4-E  Tab prefix before method";       Expect="Blocked";              Request = "`tGET / HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n" }
    @{ Name = "4-F  Header value with CR";           Expect="Blocked";              Request = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nX-Test: foo`rbar`r`nConnection: close`r`n`r`n" }
    @{ Name = "4-G  HTTP/2 preface on port 80";      Expect="Blocked";              Request = "PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n" }
    @{ Name = "4-H  OPTIONS * HTTP/1.1 (legal)";     Expect="Allowed";              Request = "OPTIONS * HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n" }
)

# ───────────────────────────────────────────
# ░ Collect all test batches and run
# ───────────────────────────────────────────
$TestBatches = @($TestBatch1, $TestBatch2, $TestBatch3, $TestBatch4)

foreach ($batch in $TestBatches) {
    Invoke-TestSuite -TestCases $batch
}

Write-Host "`nAll tests finished. Check the CSV log for results."
