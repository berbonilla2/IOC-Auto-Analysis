# ------------------- IoC Type Detection -------------------
function Get-IocType {
    param ([string]$ioc)

    if ($ioc -match '^[a-fA-F0-9]{32}$' -or $ioc -match '^[a-fA-F0-9]{40}$' -or $ioc -match '^[a-fA-F0-9]{64}$') {
        return "file"
    }
    elseif ($ioc -match '^(http|https)://') {
        return "url"
    }
    elseif ($ioc -match '^\d{1,3}(\.\d{1,3}){3}$') {
        return "ip"
    }
    elseif ($ioc -match '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
        return "domain"
    }
    elseif ($ioc -match '^[\w\.-]+@[\w\.-]+\.\w+$') {
        return "email"
    }
    else {
        return "unknown"
    }
}

# ------------------- AbuseIPDB Function -------------------
function Get-AbuseIPReport {
    param (
        [string]$ip,
        [string]$apiKey
    )

    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90"

    try {
        $headers = @{
            "Key"    = $apiKey
            "Accept" = "application/json"
        }

        $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers -ErrorAction Stop
        return $response
    }
    catch {
        Write-Warning "AbuseIPDB lookup failed for IP: ${ip} - $($_.Exception.Message)"
        return $null
    }
}

# ------------------- Convert VT JSON to CSV -------------------
function Convert-VTJsonToCsv {
    param (
        [string]$JsonFilePath,
        [string]$CsvOutputPath
    )

    Write-Host "`nConverting $JsonFilePath to CSV..."

    $jsonData = Get-Content $JsonFilePath -Raw | ConvertFrom-Json
    $flatData = @()

    $dateFields = @(
        "first_submission_date",
        "last_analysis_date",
        "last_submission_date",
        "last_modification_date"
    )

    foreach ($entry in $jsonData) {
        $ioc = $entry.IoC
        $type = $entry.Type
        $vt = $entry.VT_Response.data.attributes
        $abuse = $entry.AbuseIPDB_Data.data

        $flatRow = [ordered]@{
            IoC = $ioc
            Type = $type
        }

        foreach ($prop in $vt.PSObject.Properties) {
            if ($prop.Name -ne "last_analysis_results") {
                $value = $prop.Value
                if ($value -is [System.Array]) {
                    $flatRow["VT_" + $prop.Name] = ""
                }
                elseif ($dateFields -contains $prop.Name) {
                    try {
                        $dt = [System.DateTimeOffset]::FromUnixTimeSeconds($value).ToLocalTime()
                        $flatRow["VT_" + $prop.Name] = $dt.ToString("yyyy-MM-dd HH:mm:ss")
                    } catch {
                        $flatRow["VT_" + $prop.Name] = ""
                    }
                }
                else {
                    $flatRow["VT_" + $prop.Name] = $value
                }
            }
        }

        if ($abuse) {
            foreach ($prop in $abuse.PSObject.Properties) {
                $value = $prop.Value
                if ($value -is [System.Array]) {
                    $flatRow["Abuse_" + $prop.Name] = ""
                } else {
                    $flatRow["Abuse_" + $prop.Name] = $value
                }
            }
        }

        $flatData += [PSCustomObject]$flatRow
    }

    $flatData | Export-Csv -Path $CsvOutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV saved to $CsvOutputPath"
}

# ------------------- Convert AbuseIPDB JSON to CSV -------------------
function Convert-AbuseIPJsonToCsv {
    param (
        [string]$JsonFilePath,
        [string]$CsvOutputPath
    )

    Write-Host "`nConverting $JsonFilePath to CSV..."

    $jsonData = Get-Content $JsonFilePath -Raw | ConvertFrom-Json
    $flatData = @()

    foreach ($entry in $jsonData) {
        $ioc = $entry.IoC
        $type = $entry.Type
        $abuse = $entry.AbuseIPDB.data

        $flatRow = [ordered]@{
            IoC = $ioc
            Type = $type
        }

        if ($abuse) {
            foreach ($prop in $abuse.PSObject.Properties) {
                $value = $prop.Value
                if ($value -is [System.Array]) {
                    $flatRow["Abuse_" + $prop.Name] = ""
                } else {
                    $flatRow["Abuse_" + $prop.Name] = $value
                }
            }
        }

        $flatData += [PSCustomObject]$flatRow
    }

    $flatData | Export-Csv -Path $CsvOutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV saved to $CsvOutputPath"
}

# ------------------- Merge VT and Abuse CSV -------------------
function Merge-VTAndAbuseCsv {
    param (
        [string]$VTPath,
        [string]$AbusePath,
        [string]$OutPath
    )

    Write-Host "`nMerging $VTPath and $AbusePath..."

    $vtData = Import-Csv $VTPath
    $abuseData = Import-Csv $AbusePath

    $merged = foreach ($vt in $vtData) {
        $match = $abuseData | Where-Object { $_.IoC -eq $vt.IoC } | Select-Object -First 1
        if ($match) {
            $combined = [ordered]@{}
            foreach ($property in $vt.PSObject.Properties) {
                $combined[$property.Name] = $property.Value
            }
            foreach ($property in $match.PSObject.Properties) {
                if (-not $combined.Contains($property.Name)) {
                    $combined[$property.Name] = $property.Value
                }
            }
            [PSCustomObject]$combined
        } else {
            $vt
        }
    }

    $merged | Export-Csv -Path $OutPath -NoTypeInformation -Encoding UTF8
    Write-Host "Merged CSV saved to $OutPath"
}

# ------------------- Main Script -------------------
if (-not (Test-Path ".\api_keys.txt")) {
    Write-Error "Missing api_keys.txt file."
    exit 1
}

$allKeys = Get-Content ".\api_keys.txt" | Where-Object { $_ -and ($_ -notmatch "^#" -and $_.Trim() -ne "") }

if ($allKeys.Count -lt 2) {
    Write-Error "api_keys.txt must contain at least one VT key and one AbuseIPDB key."
    exit 1
}

$abuseIpKey = $allKeys[-1]
$vtKeys = $allKeys[0..($allKeys.Count - 2)]
$keyCount = $vtKeys.Count
$keyIndex = 0
$callCounter = 0

if (-not (Test-Path ".\ioc_input.csv")) {
    Write-Error "Missing ioc_input.csv file."
    exit 1
}

$csvData = Import-Csv ".\ioc_input.csv"

if (-not $csvData[0].PSObject.Properties.Name -contains "IoCs") {
    Write-Error "Missing 'IoCs' column in ioc_input.csv"
    exit 1
}

$iocs = $csvData | ForEach-Object { $_.IoCs } | Where-Object { $_ -ne $null -and $_ -ne "" }

if (-not $iocs -or $iocs.Count -eq 0) {
    Write-Error "No valid IoCs found in input file."
    exit 1
}

$progressFile = ".\scan_progress.txt"
Set-Content -Path $progressFile -Value "0"

$results = @()
$abuseResults = @()
Add-Type -AssemblyName System.Web

$counter = 0
$errorCount = 0

foreach ($ioc in $iocs) {
    if ($callCounter -ge 4) {
        $keyIndex = ($keyIndex + 1) % $keyCount
        $callCounter = 0
    }

    $apiKey = $vtKeys[$keyIndex]
    $callCounter++

    $type = Get-IocType -ioc $ioc
    $encoded = [System.Web.HttpUtility]::UrlEncode($ioc)

    switch ($type) {
        "domain" { $url = "https://www.virustotal.com/api/v3/domains/$encoded" }
        "ip"     { $url = "https://www.virustotal.com/api/v3/ip_addresses/$encoded" }
        "url"    {
            $urlId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ioc)).Replace("=", "").Replace("+", "-").Replace("/", "_")
            $url = "https://www.virustotal.com/api/v3/urls/$urlId"
        }
        "file"   { $url = "https://www.virustotal.com/api/v3/files/$encoded" }
        "email"  {
            Write-Warning "Skipping unsupported email IoC: $ioc"
            $counter++
            Set-Content -Path $progressFile -Value "$counter"
            continue
        }
        default {
            Write-Warning "Unknown IoC format: $ioc"
            $counter++
            Set-Content -Path $progressFile -Value "$counter"
            continue
        }
    }

    try {
        $headers = @{ "x-apikey" = $apiKey }
        $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers -ErrorAction Stop
        Write-Host ("Retrieved {0}: {1}" -f $type, $ioc)

    } catch {
        Write-Warning ("Failed to get {0} result for {1}: {2}" -f $type, $ioc, $_.Exception.Message)
        $response = $null
        $errorCount++
    }

    if ($type -eq "ip" -and $response) {
        $abuseResponse = Get-AbuseIPReport -ip $ioc -apiKey $abuseIpKey
        $abuseResults += [PSCustomObject]@{
            IoC = $ioc
            Type = "ip"
            AbuseIPDB = $abuseResponse
        }
    } else {
        $abuseResponse = $null
    }

    $results += [PSCustomObject]@{
        IoC            = $ioc
        Type           = $type
        VT_Response    = $response
        AbuseIPDB_Data = $abuseResponse
    }

    $counter++
    Set-Content -Path $progressFile -Value "$counter"
    Start-Sleep -Seconds 2
}

# -----------------------------
# Save outputs to organized folders
# -----------------------------

# Create output folders if needed
$csvFolder = ".\results\csvs"
$jsonFolder = ".\results\json"
New-Item -Path $csvFolder -ItemType Directory -Force | Out-Null
New-Item -Path $jsonFolder -ItemType Directory -Force | Out-Null

# Save VT results
$jsonOutputPath = Join-Path $jsonFolder "virustotal_results.json"
$csvOutputPath  = Join-Path $csvFolder "virustotal_results.csv"
$results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonOutputPath -Encoding UTF8
Convert-VTJsonToCsv -JsonFilePath $jsonOutputPath -CsvOutputPath $csvOutputPath

# Save AbuseIPDB results (if available)
if ($abuseResults.Count -gt 0) {
    $abuseJsonPath = Join-Path $jsonFolder "abuseipdb_results.json"
    $abuseCsvPath  = Join-Path $csvFolder "abuseipdb_results.csv"
    $abuseResults | ConvertTo-Json -Depth 10 | Set-Content -Path $abuseJsonPath -Encoding UTF8
    Convert-AbuseIPJsonToCsv -JsonFilePath $abuseJsonPath -CsvOutputPath $abuseCsvPath
} else {
    Write-Warning "No AbuseIPDB results to export."
}

# Final output summary
Write-Host "`nScan complete. Total IoCs: $counter"
Write-Host "Errors encountered: $errorCount"
Write-Host "Results saved:"
Write-Host "  - $jsonOutputPath"
Write-Host "  - $csvOutputPath"
if ($abuseJsonPath) { Write-Host "  - $abuseJsonPath" }
if ($abuseCsvPath) { Write-Host "  - $abuseCsvPath" }

if ($errorCount -gt 0) {
    exit 2
} else {
    exit 0
}
