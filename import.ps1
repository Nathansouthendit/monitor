    $key = "iCo5jK6GlQQgg53imnV9Zpt0sAN7xwAKSveZEJhghA4"
Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/ingest" -Method Post `
    -Headers @{ "X-API-Key" = $key } -ContentType "application/json" `
    -InFile "D:\Monitor\monitor\master_20261022_202426.json"