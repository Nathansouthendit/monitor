$sourcePath = "\\ymca-svr-01\housing"
$targetPath = "C:\monitor\HousingDocuments"
$date = Get-Date "06 Jan 2026"

Get-ChildItem -Path $sourcePath -Recurse -File -ErrorAction SilentlyContinue |
Where-Object {
    $_.LastWriteTime -ge $date -or $_.CreationTime -ge $date
} |
ForEach-Object {

    $relativePath = $_.FullName.Substring($sourcePath.Length).TrimStart('\')
    $destination = Join-Path $targetPath $relativePath

    $destFolder = Split-Path $destination

    if (!(Test-Path $destFolder)) {
        New-Item -ItemType Directory -Path $destFolder -Force | Out-Null
    }

    Copy-Item $_.FullName -Destination $destination -Force -ErrorAction SilentlyContinue

    Write-Host ("Copied to: " + $destination)
}