# Учебный сервер для курсовой (AJAX + JSON CRUD) без Node.js.
# Запуск:
#   powershell -ExecutionPolicy Bypass -File server.ps1
# Затем открой:
#   http://localhost:3000

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$PORT = 3000
$DB_PATH = Join-Path $ROOT "db.json"

$sessions = @{} # token -> @{ username=...; csrfToken=...; exp=... }

function New-RandomHex([int]$bytes){
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $data = New-Object byte[] $bytes
    $rng.GetBytes($data)
    return ([System.BitConverter]::ToString($data) -replace "-", "").ToLowerInvariant()
  } finally {
    $rng.Dispose()
  }
}

function Sha256Hex([string]$input){
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$input)
    $hash = $sha.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hash) -replace "-", "").ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

function Read-JsonFile(){
  if(!(Test-Path $DB_PATH)){
    $seed = [ordered]@{
      users = @()
      properties = @()
    } | ConvertTo-Json -Depth 10
    $seed | Out-File -Encoding utf8 -FilePath $DB_PATH
  }
  $raw = Get-Content -Raw -Encoding utf8 $DB_PATH
  if([string]::IsNullOrWhiteSpace($raw)){
    return [ordered]@{ users=@(); properties=@() }
  }
  $db = $raw | ConvertFrom-Json
  if($null -eq $db.users){ $db | Add-Member -NotePropertyName users -NotePropertyValue @() -Force }
  if($null -eq $db.properties){ $db | Add-Member -NotePropertyName properties -NotePropertyValue @() -Force }
  return $db
}

function Write-Db($db){
  $db | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 -FilePath $DB_PATH
}

function SanitizeText($s, [int]$maxLen){
  $t = [string]$s
  if($null -eq $t){ $t = "" }
  $t = $t.Replace("<","&lt;").Replace(">","&gt;")
  if($t.Length -gt $maxLen){
    $t = $t.Substring(0,$maxLen)
  }
  return $t
}

function Json-Response($res, [int]$statusCode, $obj){
  $body = $obj | ConvertTo-Json -Depth 10
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
  $res.StatusCode = $statusCode
  $res.ContentType = "application/json; charset=utf-8"
  $res.ContentLength64 = $bytes.Length
  $res.OutputStream.Write($bytes,0,$bytes.Length)
  $res.OutputStream.Close()
}

function Get-SessionFromRequest($req){
  $auth = $req.Headers["Authorization"]
  if([string]::IsNullOrWhiteSpace($auth)){
    return $null
  }
  $m = [regex]::Match($auth, "^Bearer\s+(.+)$")
  if(!$m.Success){
    return $null
  }
  $token = $m.Groups[1].Value
  if(!$sessions.ContainsKey($token)){
    return $null
  }
  $sess = $sessions[$token]
  if([DateTimeOffset]::FromUnixTimeMilliseconds($sess.exp) -lt [DateTimeOffset]::UtcNow){
    $sessions.Remove($token) | Out-Null
    return $null
  }
  return $sess
}

function Must-Auth($req, $res){
  $session = Get-SessionFromRequest $req
  if($null -eq $session){
    Json-Response $res 401 @{ ok=$false; message="Unauthorized" }
    return $null
  }
  $csrf = $req.Headers["X-CSRF-Token"]
  if([string]::IsNullOrWhiteSpace($csrf) -or $csrf -ne $session.csrfToken){
    Json-Response $res 403 @{ ok=$false; message="CSRF token mismatch" }
    return $null
  }
  return $session
}

function Ensure-DemoAndSeeds(){
  $db = Read-JsonFile

  $hasDemo = $db.users | Where-Object { $_.username -eq "demo" } | Select-Object -First 1
  if($null -eq $hasDemo){
    $salt = New-RandomHex 16
    if($null -eq $db.users){ $db.users=@() }
    if($db.users -isnot [System.Array]){ $db.users=@($db.users) }
    $db.users += [ordered]@{
      id = ($db.users.Count + 1)
      username = "demo"
      salt = $salt
      passwordHash = (Sha256Hex ($salt + "::" + "demo123"))
      createdAt = (Get-Date).ToString("o")
    }
    Write-Db $db
  }

  if($db.properties -eq $null){ $db.properties=@() }
  # properties seed intentionally empty (пользователь создаёт объявления в UI)
}

Ensure-DemoAndSeeds

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$PORT/")
$listener.Start()
Write-Host "Server started: http://localhost:$PORT"

while($listener.IsListening){
  $ctx = $null
  try{
    $ctx = $listener.GetContext()
    $req = $ctx.Request
    $res = $ctx.Response

    $path = $req.Url.AbsolutePath
    $method = $req.HttpMethod

    # SPA: отдаём index.html
    if($path -eq "/" -or $path -eq "/index.html"){
      $filePath = Join-Path $ROOT "index.html"
      $bytes = [System.IO.File]::ReadAllBytes($filePath)
      $res.StatusCode = 200
      $res.ContentType = "text/html; charset=utf-8"
      $res.ContentLength64 = $bytes.Length
      $res.OutputStream.Write($bytes,0,$bytes.Length)
      $res.OutputStream.Close()
      continue
    }

    # API
    if($path.StartsWith("/api/")){
      # Auth register
      if($path -eq "/api/auth/register" -and $method -eq "POST"){
        $bodyStr = (New-Object System.IO.StreamReader($req.InputStream)).ReadToEnd()
        if([string]::IsNullOrWhiteSpace($bodyStr)){ $bodyStr="{}" }
        $body = $bodyStr | ConvertFrom-Json
        $username = ([string]$body.username).Trim()
        $password = [string]$body.password

        if($username.Length -lt 3 -or $username.Length -gt 24){
          Json-Response $res 400 @{ ok=$false; message="Логин должен быть от 3 до 24 символов" }
          continue
        }
        if(-not ($username -match "^[a-zA-Z0-9_]+$")){
          Json-Response $res 400 @{ ok=$false; message="Логин допускает только латиницу/цифры/подчеркивание" }
          continue
        }
        if($password.Length -lt 6){
          Json-Response $res 400 @{ ok=$false; message="Пароль должен быть минимум 6 символов" }
          continue
        }

        $db = Read-JsonFile
        $exists = $db.users | Where-Object { $_.username -eq $username } | Select-Object -First 1
        if($null -ne $exists){
          Json-Response $res 409 @{ ok=$false; message="Пользователь с таким логином уже существует" }
          continue
        }

        $salt = New-RandomHex 16
        if($null -eq $db.users){ $db.users=@() }
        if($db.users -isnot [System.Array]){ $db.users=@($db.users) }
        $db.users += [ordered]@{
          id = ($db.users.Count + 1)
          username = $username
          salt = $salt
          passwordHash = (Sha256Hex ($salt + "::" + $password))
          createdAt = (Get-Date).ToString("o")
        }
        Write-Db $db
        Json-Response $res 200 @{ ok=$true; message="Регистрация прошла успешно" }
        continue
      }

      # Auth login
      if($path -eq "/api/auth/login" -and $method -eq "POST"){
        $bodyStr = (New-Object System.IO.StreamReader($req.InputStream)).ReadToEnd()
        if([string]::IsNullOrWhiteSpace($bodyStr)){ $bodyStr="{}" }
        $body = $bodyStr | ConvertFrom-Json
        $username = ([string]$body.username).Trim()
        $password = [string]$body.password

        $db = Read-JsonFile
        $user = $db.users | Where-Object { $_.username -eq $username } | Select-Object -First 1
        if($null -eq $user){
          Json-Response $res 401 @{ ok=$false; message="Неверный логин или пароль" }
          continue
        }
        $expected = Sha256Hex ($user.salt + "::" + $password)
        if($expected -ne $user.passwordHash){
          Json-Response $res 401 @{ ok=$false; message="Неверный логин или пароль" }
          continue
        }

        $token = New-RandomHex 24
        $csrfToken = New-RandomHex 16
        $exp = ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + (60*60*1000))
        $sessions[$token] = @{ username=$username; csrfToken=$csrfToken; exp=$exp }
        Json-Response $res 200 @{ ok=$true; token=$token; csrfToken=$csrfToken }
        continue
      }

      # Auth me
      if($path -eq "/api/auth/me" -and $method -eq "GET"){
        $session = Get-SessionFromRequest $req
        if($null -eq $session){
          Json-Response $res 401 @{ ok=$false; message="Unauthorized" }
          continue
        }
        $csrf = $req.Headers["X-CSRF-Token"]
        if($null -ne $csrf -and $csrf -ne "" -and $csrf -ne $session.csrfToken){
          Json-Response $res 403 @{ ok=$false; message="CSRF token mismatch" }
          continue
        }
        Json-Response $res 200 @{ ok=$true; username=$session.username; csrfToken=$session.csrfToken }
        continue
      }

      # Properties: /api/properties
      if($path -eq "/api/properties" -and $method -eq "GET"){
        $session = Get-SessionFromRequest $req
        if($null -eq $session){
          Json-Response $res 401 @{ ok=$false; message="Unauthorized" }
          continue
        }
        $db = Read-JsonFile
        $mine = @()
        foreach($p in $db.properties){
          if([string]$p.owner -eq [string]$session.username){
            $mine += $p
          }
        }
        Json-Response $res 200 @{ ok=$true; properties=$mine }
        continue
      }

      if($path -eq "/api/properties" -and $method -eq "POST"){
        $session = Must-Auth $req $res
        if($null -eq $session){ continue }

        $bodyStr = (New-Object System.IO.StreamReader($req.InputStream)).ReadToEnd()
        if([string]::IsNullOrWhiteSpace($bodyStr)){ $bodyStr="{}" }
        $body = $bodyStr | ConvertFrom-Json

        $title = SanitizeText $body.title 80
        $address = SanitizeText $body.address 120
        $type = SanitizeText $body.type 20
        $description = SanitizeText $body.description 2000
        $rooms = [double]$body.rooms
        $area = [double]$body.area
        $price = [double]$body.price

        if([string]::IsNullOrWhiteSpace($title) -or $title.Length -lt 3){
          Json-Response $res 400 @{ ok=$false; message="Некорректный заголовок" }
          continue
        }
        if([string]::IsNullOrWhiteSpace($address) -or $address.Length -lt 5){
          Json-Response $res 400 @{ ok=$false; message="Некорректный адрес" }
          continue
        }
        if($rooms -lt 0){
          Json-Response $res 400 @{ ok=$false; message="Некорректное число комнат" }
          continue
        }
        if($area -le 0){
          Json-Response $res 400 @{ ok=$false; message="Некорректная площадь" }
          continue
        }
        if($price -le 0){
          Json-Response $res 400 @{ ok=$false; message="Некорректная цена" }
          continue
        }

        $db = Read-JsonFile
        if($null -eq $db.properties){ $db.properties=@() }
        $maxId = 0
        foreach($p in $db.properties){
          if([int]$p.id -gt $maxId){ $maxId=[int]$p.id }
        }
        $nextId = $maxId + 1

        $property = [ordered]@{
          id = $nextId
          owner = $session.username
          createdAt = (Get-Date).ToString("o")
          updatedAt = $null
          title = $title
          address = $address
          type = $type
          rooms = [int]$rooms
          area = $area
          price = $price
          description = $description
        }

        # Unshift
        $db.properties = @($property) + @($db.properties)
        Write-Db $db
        Json-Response $res 201 @{ ok=$true; property=$property }
        continue
      }

      # /api/properties/{id}
      $m = [regex]::Match($path, "^/api/properties/(\d+)$")
      if($m.Success){
        $id = [int]$m.Groups[1].Value
        $session = Must-Auth $req $res
        if($null -eq $session){ continue }

        $db = Read-JsonFile
        $idx = -1
        for($i=0; $i -lt $db.properties.Count; $i++){
          $p = $db.properties[$i]
          if([int]$p.id -eq $id -and [string]$p.owner -eq [string]$session.username){
            $idx = $i
            break
          }
        }
        if($idx -eq -1){
          Json-Response $res 404 @{ ok=$false; message="Объявление не найдено" }
          continue
        }

        if($method -eq "PUT"){
          $bodyStr = (New-Object System.IO.StreamReader($req.InputStream)).ReadToEnd()
          if([string]::IsNullOrWhiteSpace($bodyStr)){ $bodyStr="{}" }
          $body = $bodyStr | ConvertFrom-Json

          $title = SanitizeText $body.title 80
          $address = SanitizeText $body.address 120
          $type = SanitizeText $body.type 20
          $description = SanitizeText $body.description 2000
          $rooms = [double]$body.rooms
          $area = [double]$body.area
          $price = [double]$body.price
          if([string]::IsNullOrWhiteSpace($title) -or $title.Length -lt 3){
            Json-Response $res 400 @{ ok=$false; message="Некорректный заголовок" }
            continue
          }
          if([string]::IsNullOrWhiteSpace($address) -or $address.Length -lt 5){
            Json-Response $res 400 @{ ok=$false; message="Некорректный адрес" }
            continue
          }
          if($rooms -lt 0){
            Json-Response $res 400 @{ ok=$false; message="Некорректное число комнат" }
            continue
          }
          if($area -le 0){
            Json-Response $res 400 @{ ok=$false; message="Некорректная площадь" }
            continue
          }
          if($price -le 0){
            Json-Response $res 400 @{ ok=$false; message="Некорректная цена" }
            continue
          }

          $old = $db.properties[$idx]
          $updated = [ordered]@{
            id = $old.id
            owner = $old.owner
            createdAt = $old.createdAt
            updatedAt = (Get-Date).ToString("o")
            title = $title
            address = $address
            type = $type
            rooms = [int]$rooms
            area = $area
            price = $price
            description = $description
          }
          $db.properties[$idx] = $updated
          Write-Db $db
          Json-Response $res 200 @{ ok=$true; property=$updated }
          continue
        }

        if($method -eq "DELETE"){
          $removed = $db.properties[$idx]
          # delete item
          $before = @()
          $after = @()
          if($idx -gt 0){
            $before = @($db.properties[0..($idx-1)])
          }
          if($idx -lt ($db.properties.Count - 1)){
            $after = @($db.properties[($idx+1)..($db.properties.Count-1)])
          }
          $db.properties = @($before) + @($after)
          Write-Db $db
          Json-Response $res 200 @{ ok=$true; deleted=$removed }
          continue
        }
      }

      Json-Response $res 404 @{ ok=$false; message="API endpoint not found" }
      continue
    }

    # Статика: отдаём index.html по умолчанию
    $filePath2 = Join-Path $ROOT "index.html"
    $bytes2 = [System.IO.File]::ReadAllBytes($filePath2)
    $res.StatusCode = 200
    $res.ContentType = "text/html; charset=utf-8"
    $res.ContentLength64 = $bytes2.Length
    $res.OutputStream.Write($bytes2,0,$bytes2.Length)
    $res.OutputStream.Close()
  }catch{
    if($ctx -ne $null){
      try{ Json-Response $ctx.Response 500 @{ ok=$false; message="Server error" } }catch{}
    }
  }
}

$listener.Stop()

