<#
  End-to-end security smoke test (Windows PowerShell 5.1+ / PowerShell 7).

  Usage, with the stack already running:
      .\scripts\load-env.ps1        # makes BOOTSTRAP_ADMIN_USERNAME/PASSWORD available
      .\scripts\smoke-test.ps1

  Notes
  - Registers one throw-away user per run. Register/login are rate limited per IP, so wait about
    10 minutes (or restart Redis) before running it twice in a row.
  - -SkipRateLimit skips the final 429 check. Admin checks are skipped if no admin credentials are set.
#>
param(
    [string]$BaseUrl = 'http://localhost:8080',
    [string]$AdminUser = $env:BOOTSTRAP_ADMIN_USERNAME,
    [string]$AdminPassword = $env:BOOTSTRAP_ADMIN_PASSWORD,
    [switch]$SkipRateLimit
)

Add-Type -AssemblyName System.Net.Http
$ErrorActionPreference = 'Stop'
$script:passed = 0
$script:failed = 0

function Invoke-Api {
    param([string]$Method, [string]$Url, $Body = $null, [string]$Token = $null)
    $headers = @{}
    if ($Token) { $headers['Authorization'] = "Bearer $Token" }
    $params = @{ Uri = $Url; Method = $Method; Headers = $headers; UseBasicParsing = $true }
    if ($null -ne $Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Compress)
        $params['ContentType'] = 'application/json'
    }
    try {
        $r = Invoke-WebRequest @params
        return @{ Status = [int]$r.StatusCode; Body = [string]$r.Content; Headers = $r.Headers }
    }
    catch {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { return @{ Status = 0; Body = $_.Exception.Message; Headers = @{} } }
        $status = [int]$resp.StatusCode
        if ($resp -is [System.Net.Http.HttpResponseMessage]) {
            $content = $resp.Content.ReadAsStringAsync().Result
        }
        else {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $content = $reader.ReadToEnd()
        }
        return @{ Status = $status; Body = [string]$content; Headers = $resp.Headers }
    }
}

function Check([string]$name, $actual, $expected) {
    if ($actual -eq $expected) { Write-Host "[PASS] $name (HTTP $actual)" -ForegroundColor Green; $script:passed++ }
    else { Write-Host "[FAIL] $name - expected $expected, got $actual" -ForegroundColor Red; $script:failed++ }
}

function Check-True([string]$name, [bool]$condition, [string]$detail = '') {
    if ($condition) { Write-Host "[PASS] $name" -ForegroundColor Green; $script:passed++ }
    else { Write-Host "[FAIL] $name $detail" -ForegroundColor Red; $script:failed++ }
}

$suffix = -join ((97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
$user = "smoke$suffix"
$pw = "Sm0ke-Test-$suffix-Pw1"

Write-Host "`n--- Registration and input validation ---"
$r = Invoke-Api POST "$BaseUrl/auth/register" @{ username = $user; password = $pw }
Check 'Register new user' $r.Status 201
$r = Invoke-Api POST "$BaseUrl/auth/register" @{ username = $user; password = $pw }
Check 'Duplicate username rejected' $r.Status 409
$r = Invoke-Api POST "$BaseUrl/auth/register" @{ username = "weak$suffix"; password = 'short' }
Check 'Weak password rejected' $r.Status 400
$r = Invoke-Api POST "$BaseUrl/auth/register" @{ username = "evil$suffix"; password = $pw; role = 'ADMIN' }
Check 'Self-assigned ADMIN role rejected (unknown field)' $r.Status 400

Write-Host "`n--- Authentication ---"
$r = Invoke-Api POST "$BaseUrl/auth/login" @{ username = $user; password = 'Wrong-Password-123' }
Check 'Wrong password -> 401' $r.Status 401
$r = Invoke-Api POST "$BaseUrl/auth/login" @{ username = $user; password = $pw }
Check 'Valid login' $r.Status 200
$token = ($r.Body | ConvertFrom-Json).accessToken
Check-True 'Login response contains an access token' (-not [string]::IsNullOrEmpty($token))
Check-True 'Security header X-Content-Type-Options present' ([string]($r.Headers['X-Content-Type-Options']) -eq 'nosniff')
Check-True 'Server version header not disclosed' ([string]::IsNullOrEmpty([string]($r.Headers['Server'])))

$r = Invoke-Api GET "$BaseUrl/products"
Check 'No token -> 401' $r.Status 401
$tampered = $token.Substring(0, $token.Length - 2) + 'xx'
$r = Invoke-Api GET "$BaseUrl/products" $null $tampered
Check 'Tampered token -> 401' $r.Status 401

Write-Host "`n--- Authorization (roles enforced server-side) ---"
$r = Invoke-Api GET "$BaseUrl/products" $null $token
Check 'CUSTOMER can list products' $r.Status 200
$r = Invoke-Api POST "$BaseUrl/products" @{ name = 'Phone'; price = 499.99 } $token
Check 'CUSTOMER cannot create products' $r.Status 403
$r = Invoke-Api GET "$BaseUrl/auth/admin/users" $null $token
Check 'CUSTOMER cannot reach admin routes' $r.Status 403

Write-Host "`n--- Route and path control ---"
$r = Invoke-Api GET "$BaseUrl/nope"
Check 'Unknown route -> 404' $r.Status 404
$r = Invoke-Api GET "$BaseUrl/products/abc%20def" $null $token
Check 'Unsafe path characters -> 400' $r.Status 400
$r = Invoke-Api PUT "$BaseUrl/products/1" @{ name = 'x'; price = 1 } $token
Check 'Method not in policy -> 405' $r.Status 405

Write-Host "`n--- Backends are not directly usable ---"
$r = Invoke-Api GET 'http://localhost:8082/products'
Check-True 'Direct call to product-service refused (403 or unreachable)' (($r.Status -eq 403) -or ($r.Status -eq 0)) "(got $($r.Status))"

if ($AdminUser -and $AdminPassword) {
    Write-Host "`n--- Admin flows ---"
    $r = Invoke-Api POST "$BaseUrl/auth/login" @{ username = $AdminUser; password = $AdminPassword }
    Check 'Admin login' $r.Status 200
    $adminToken = ($r.Body | ConvertFrom-Json).accessToken
    $r = Invoke-Api POST "$BaseUrl/products" @{ name = 'Smoke Laptop'; price = 999.99 } $adminToken
    Check 'ADMIN can create product' $r.Status 201
    $productId = ($r.Body | ConvertFrom-Json).id
    $r = Invoke-Api POST "$BaseUrl/products" @{ name = '<script>alert(1)</script>'; price = 5 } $adminToken
    Check 'HTML/script in product name rejected' $r.Status 400
    $r = Invoke-Api GET "$BaseUrl/products/$productId" $null $adminToken
    Check 'ADMIN can read product by id' $r.Status 200
    $r = Invoke-Api GET "$BaseUrl/auth/admin/users" $null $adminToken
    Check 'ADMIN can list users' $r.Status 200
    Check-True 'User listing never contains password hashes' (-not ($r.Body -match 'password|\$2[aby]\$'))
    $r = Invoke-Api DELETE "$BaseUrl/products/$productId" $null $adminToken
    Check 'ADMIN can delete product' $r.Status 204
}
else {
    Write-Host "`n[SKIP] Admin flows - set BOOTSTRAP_ADMIN_USERNAME/PASSWORD (run load-env.ps1) to include them." -ForegroundColor Yellow
}

if (-not $SkipRateLimit) {
    Write-Host "`n--- Login rate limiting (uses a non-existent user, so no real account gets locked) ---"
    $limited = $false
    1..15 | ForEach-Object {
        $r = Invoke-Api POST "$BaseUrl/auth/login" @{ username = "nobody$suffix"; password = 'Wrong-Password-123' }
        if ($r.Status -eq 429) { $limited = $true; $retry = [string]($r.Headers['Retry-After']) }
    }
    Check-True 'Repeated bad logins eventually return 429' $limited
    if ($limited) { Check-True 'Retry-After header present on 429' (-not [string]::IsNullOrEmpty($retry)) }
}

Write-Host "`nResult: $($script:passed) passed, $($script:failed) failed"
if ($script:failed -gt 0) { exit 1 }
