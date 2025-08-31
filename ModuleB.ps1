Param (
    [string]$Aspect
)

if ($Aspect) {
    $AspectNorm = $Aspect.ToUpper().Replace(".", "")
}

function Should-Run {
    param([string]$Target)   # e.g. "B1M3" or "B1"
    if (-not $AspectNorm) { return $true }       # run all
    if ($AspectNorm -eq $Target) { return $true } # exact
    if ($AspectNorm -eq ($Target -replace '[MJ]\d+$','')) { return $true } # module
    return $false
}

function Test-AspectSteps {
    param(
        [string]$Aspect,
        [string]$Description,
        [array] $Steps,                  # each: @{ Name=''; Cmd=''; Expected=''; PassIf={param($out)$true}; Ip=''; User=''; SshKey=''; JumpIp=''; JumpUser=''; Local=$false; Manual=$false; Instructions='' }
        [string]$DefaultUser="Administrator",
        [string]$DefaultSshKey="C:\Resource\ModuleB",
        [string]$DefaultJumpUser="Administrator",
        [string]$DefaultIp,
        [switch]$DefaultManual=$False,
        [switch]$DefaultLocal=$False
    )

    Clear-Host
    Write-Host "----------------------------------------------------------"
    Write-Host "Testing aspect $Aspect"
    Write-Host $Description

    $autoScore = 0
    $autoTotal = 0
    $stepCounter = 0

    foreach ($s in $Steps) {
        $stepCounter++
        $name     = $s.Name
        $cmd      = $s.Cmd
        $expected = $s.Expected
        $passIf   = $s.PassIf
        $ip       = if ($s.ContainsKey('Ip') -and $s.Ip) {$s.Ip} else { $DefaultIp }
        $user     = if ($s.ContainsKey('User') -and $s.User) { $s.User } else { $DefaultUser }
        $sshKey   = if ($s.ContainsKey('SshKey') -and $s.SshKey) { $s.SshKey } else { $DefaultSshKey }
        $jumpIp   = $s.JumpIp
        $jumpUser = if ($s.ContainsKey('JumpUser') -and $s.JumpUser) { $s.JumpUser } else { $DefaultJumpUser }
        $local    = if ($s.ContainsKey('Local'))  { [bool]$s.Local }  else { [bool]$DefaultLocal }        $manual   = if ($s.ContainsKey('Manual')) { [bool]$s.Manual } else { [bool]$DefaultManual }
        $instr    = $s.Instructions

        Write-Host ""
        Write-Host ("[{0}/{1}] {2}" -f $stepCounter, $Steps.Count, $name) -ForegroundColor Gray

        if ($manual) {
            Write-Host "!!! MANUAL TESTING !!!"
            if ($instr) { Write-Host $instr }
            Write-Host "Expected:" -NoNewline; Write-Host " $expected" -ForegroundColor Cyan
            continue
        }

        # --- automated step ---
        $autoTotal++

        # run the command (SSH / jump / local)
        $res = if ($local) {
            try { Invoke-Expression $cmd } catch { "ERROR: $($_.Exception.Message)" }
        } elseif ($jumpIp) {
            ssh -o ProxyCommand="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $sshKey -W %h:%p $jumpUser@$jumpIp" `
                -o StrictHostKeyChecking=no -i $sshKey "$user@$ip" "try { $cmd } catch { Write-Host 'Command: ""$cmd"" threw an error' }"
        } else {
            ssh -o StrictHostKeyChecking=no -i $sshKey "$user@$ip" "try { $cmd } catch { Write-Host 'Command: ""$cmd"" threw an error' }"
        }

        $actual = ($res | Out-String).Trim()

        Write-Host "Expected: $expected" -ForegroundColor Cyan
        Write-Host "Actual  :" -ForegroundColor White
        Write-Host "----- OUTPUT START -----" -ForegroundColor DarkGray
        Write-Host $actual -ForegroundColor White
        Write-Host "-----  OUTPUT END  -----" -ForegroundColor DarkGray        
        
        # PASS/FAIL logic:
        # - if PassIf provided, use it
        # - otherwise do a reasonable default:
        #     * if Expected is 'TRUE' or 'FALSE' -> token match
        #     * else treat Expected as a regex that must be found in Actual
        $ok = $false
        try {
            if ($passIf) {
                $ok = & $passIf $actual
            } else {
                switch -regex ($expected) {
                    '^\s*TRUE\s*$'  { $ok = ($actual -match '\bTrue\b'); break }
                    '^\s*FALSE\s*$' { $ok = ($actual -match '\bFalse\b'); break }
                    default         { $ok = [bool]([regex]::IsMatch($actual, $expected, 'IgnoreCase')) }
                }
            }
        } catch { $ok = $false }

        if ($ok) { $autoScore++; Write-Host "Result: PASS" -ForegroundColor Green }
        else     {               Write-Host "Result: FAIL" -ForegroundColor Red   }
    }

    Write-Host ""
    Write-Host ("Score: {0}/{1} (automated steps only)" -f $autoScore, $autoTotal) -ForegroundColor Yellow

    Write-Host "Please mark now aspect " -NoNewline
    Write-Host "$Aspect" -ForegroundColor Red
    $confirmation = Read-Host "Move to the next aspect? [y/n]"
    while($confirmation -ne "y")
    {
        if ($confirmation -eq 'n') { exit }
        $confirmation = Read-Host "Move to the next aspect? [y/n]"
    }
}

# B1.M1 - RAS: RTR-AAL internal IP addresses are reachable
if (Should-Run "B1M1") {
    Test-AspectSteps -Aspect "B1.M1" -Description "RAS: RTR-AAL internal IP addresses are reachable" `
        -DefaultIp "10.1.1.254" -Steps @(
            @{
                Name     = "RTR-AAL: IPv4 address is reachable"
                Cmd      = "(Test-NetConnection 10.2.1.254 -WarningAction SilentlyContinue).PingSucceeded"
                Expected = "True"
            },
            @{
                Name     = "RTR-AAL: IPv6 address is reachable"
                Cmd      = "(Test-NetConnection fd01:2:1::254 -WarningAction SilentlyContinue).PingSucceeded"
                Expected = "True"
            }
        )
}

# B1.M2 - RAS: Site-to-Site VPN is active
if (Should-Run "B1M2") {
    Test-AspectSteps -Aspect "B1.M2" -Description "RAS: Site-to-Site VPN is active" `
        -DefaultIp "10.1.1.254" -Steps @(
            @{
                Name     = "RTR-CPH: Site-to-Site VPN is active"
                Cmd      = "(Get-VpnS2SInterface).ConnectionState"
                Expected = "Connected"
            }
        )
}

# B1.M3 - RAS: Firewall is configured to block TCP/8080 + WinRM
if (Should-Run "B1M3") {
    Test-AspectSteps -Aspect "B1.M3" -Description "RAS: Firewall is configured to block TCP/8080 + WinRM" `
        -DefaultIp "10.1.1.254" -Steps @(
            @{
                Name     = "RTR-CPH: TCP/8080 is blocked"
                Cmd      = "netsh routing ip show filter name=Ethernet0"
                Expected = "TCP/8080 is listed"
                PassIf = { param($o) $o -match '\b8080\b' }
            },
            @{
                Name     = "RTR-CPH: WINRM is blocked"
                Cmd      = "netsh routing ip show filter name=Ethernet0"
                Expected = "TCP/5985 is listed"
                PassIf = { param($o) $o -match '\b5985\b' }
            }
        )
}

# B1.M4 - RAS: Port forward web service
if (Should-Run "B1M4") {
    Test-AspectSteps -Aspect "B1.M4" -Description "RAS: Port forward web service" `
        -DefaultIp "10.1.1.254" -Steps @(
            @{
                Name     = "RTR-AAL: Port forward web service"
                Cmd      = "netsh routing ip nat show interface"
                Expected = "Port forward 8080 -> 80"
                PassIf = { param($o) ($o -match '\b8080\b') -and ($o -match '\b80\b') }
            }
        )
}

# B1.M5 - RAS: NAT is configured
if (Should-Run "B1M5") {
    Test-AspectSteps -Aspect "B1.M5" -Description "RAS: NAT is configured" `
        -DefaultIp "10.1.1.254" -Steps @(
            @{
                Name     = "RTR-CPH: NAT is configured"
                Cmd      = "netsh routing ip nat show interface"
                Expected = "Mode: Address and Port Translation"
                PassIf = { param($o) $o -match '\bAddress and Port Translation\b' }
            }
        )
}

# B2.M1 - RAS: DC internal IP addresses are reachable
if (Should-Run "B2M1") {
    Test-AspectSteps -Aspect "B2.M1" -Description "RAS: DC internal IP addresses are reachable" `
        -DefaultIp "10.2.1.254" -Steps @(
            @{
                Name     = "DC: IPv4 address is reachable"
                Cmd      = "(Test-NetConnection 10.1.1.254 -WarningAction SilentlyContinue).PingSucceeded"
                Expected = "True"
            },
            @{
                Name     = "DC: IPv6 address is reachable"
                Cmd      = "(Test-NetConnection fd01:1:1::254 -WarningAction SilentlyContinue).PingSucceeded"
                Expected = "True"
            }
        )

}

# B2.M2 - RAS: NAT is configured
if (Should-Run "B2M2") {
    Test-AspectSteps -Aspect "B2.M2" -Description "RAS: NAT is configured" `
        -DefaultIp "10.2.1.254" -Steps @(
            @{
                Name     = "RTR-AAL: NAT is configured"
                Cmd      = "netsh routing ip nat show interface"
                Expected = "Mode: Address and Port Translation"
                PassIf = { param($o) $o -match '\bAddress and Port Translation\b' }
            }
        )
}

# B3.M1 - ADDS: skillsnet.dk forest root
if (Should-Run "B3M1") {
    Test-AspectSteps -Aspect "B3.M1" -Description "ADDS: skillsnet.dk forest root" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "RTR-AAL: IPv4 address is reachable"
                Cmd      = "Get-ADForest | Select RootDomain, SchemaMaster"
                Expected = "RootDomain=skillsnet.dk; SchemaMaster=DC.skillsnet.dk"
                PassIf   = { param($o) 
                    ($o -match 'skillsnet\.dk') -and ($o -match 'DC\.skillsnet\.dk') 
                }
            }
        )
}

# B3.M2 - ADDS: sites Copenhagen and Aalborg are configured
if (Should-Run "B3M2") {
    Test-AspectSteps -Aspect "B3.M2" -Description "ADDS: sites Copenhagen and Aalborg are configured" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "DC: Sites Copenhagen and Aalborg exist"
                Cmd      = "(Get-ADForest).Sites"
                Expected = "Sites - Copenhagen and Aalborg"
                PassIf = { param($o) 
                    ($o -match '\bCopenhagen\b') -and ($o -match '\bAalborg\b') 
                }
            }
        )
}

# B3.M3 - ADDS: DCs are at respective sites
if (Should-Run "B3M3") {
    Test-AspectSteps -Aspect "B3.M3" -Description "ADDS: DCs are at respective sites" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "DCs are at respective sites - DC"
                Cmd      = "Get-ADDomainController -Filter * | Select-Object Name, Site"
                Expected = "DC is located at Copenhagen site"
                PassIf = { param($o)
                    ($o -split "\r?\n" | Where-Object { $_ -match '^\s*DC\s+Copenhagen\s*$' }).Count -gt 0
                }                  
            },
            @{
                Name     = "DCs are at respective sites - RODC"
                Cmd      = "Get-ADDomainController -Filter * | Select-Object Name, Site"
                Expected = "RODC is located at Aalborg site"
                PassIf = { param($o)
                    ($o -split "\r?\n" | Where-Object { $_ -match '^\s*RODC\s+Aalborg\s*$' }).Count -gt 0
                }    
            }
        )
}

# B3.M4 - ADDS: OU structure according to requirements
if (Should-Run "B3M4") {
    Test-AspectSteps -Aspect "B3.M4" -Description "ADDS: OU structure according to requirements" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "DC: OU structure according to requirements"
                Cmd      = "Import-Module ActiveDirectory -ErrorAction Stop; Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName"
                Expected = "Skills, Skills\Users, Skills\Groups, Skills\Desktops, Skills\Servers, Skills\Employees, Skills\Contractors"
                PassIf   = {
                    param($o)
                    $expectedOUs = @(
                        'OU=Users,OU=Skills,DC=skillsnet,DC=dk',
                        'OU=Groups,OU=Skills,DC=skillsnet,DC=dk',
                        'OU=Desktops,OU=Skills,DC=skillsnet,DC=dk',
                        'OU=Servers,OU=Skills,DC=skillsnet,DC=dk',
                        'OU=Employees,OU=Users,OU=Skills,DC=skillsnet,DC=dk',
                        'OU=Contractors,OU=Users,OU=Skills,DC=skillsnet,DC=dk',
                        'OU=Skills,DC=skillsnet,DC=dk'
                    )
                    foreach ($e in $expectedOUs) {
                        if ($o -notmatch [regex]::Escape($e)) { return $false }
                    }
                    return $true
                }
            }
        )
}

# B3.M5 - Separate script


# B3.M6 - ADDS: FGPP polices are configured
if (Should-Run "B3M6") {
    Test-AspectSteps -Aspect "B3.M6" -Description "ADDS: FGPP polices are configured" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "ADDS Policy: FGPP-Users"
                Cmd      = "Get-ADFineGrainedPasswordPolicy FGPP-Users |  Select-Object  Name, MinPasswordLength, MaxPasswordAge, ComplexityEnabled, LockoutThreshold, LockoutDuration, AppliesTo"
                Expected = "FGPP-Users: MinLength=12, MaxAge=730 days, Complexity=Yes, Lockout=5 attempts/5 minutes, Applies=Regular users"
                PassIf   = {
                    param($o)
                    ($o -match 'Name\s*:\s*FGPP-Users') -and
                    ($o -match 'MinPasswordLength\s*:\s*12') -and
                    ($o -match 'MaxPasswordAge\s*:\s*730\.00:00:00') -and
                    ($o -match 'ComplexityEnabled\s*:\s*True') -and
                    ($o -match 'LockoutThreshold\s*:\s*5') -and
                    ($o -match 'LockoutDuration\s*:\s*00:05:00') -and
                    ($o -match 'Employees')
                }
            },
            @{
                Name     = "ADDS Policy: FGPP-Tech"
                Cmd      = "Get-ADFineGrainedPasswordPolicy FGPP-Tech |  Select-Object  Name, MinPasswordLength, MaxPasswordAge, ComplexityEnabled, LockoutThreshold, LockoutDuration, AppliesTo"
                Expected = "FGPP-Tech: MinLength=20, MaxAge=365 days, Complexity=Yes, Lockout=3 attempts/15 minutes, Applies=Tech"
                PassIf   = {
                    param($o)
                    ($o -match 'Name\s*:\s*FGPP-Tech') -and
                    ($o -match 'MinPasswordLength\s*:\s*20') -and
                    ($o -match 'MaxPasswordAge\s*:\s*365\.00:00:00') -and
                    ($o -match 'ComplexityEnabled\s*:\s*True') -and
                    ($o -match 'LockoutThreshold\s*:\s*3') -and
                    ($o -match 'LockoutDuration\s*:\s*00:15:00') -and
                    ($o -match 'Tech')
                }
            },
            @{
                Name     = "ADDS Policy: FGPP-Contractors"
                Cmd      = "Get-ADFineGrainedPasswordPolicy FGPP-Contractors |  Select-Object  Name, MinPasswordLength, MaxPasswordAge, ComplexityEnabled, LockoutThreshold, LockoutDuration, AppliesTo"
                Expected = "FGPP-Contractors: MinLength=16, MaxAge=90 days, Complexity=Yes, Lockout=3 attempts/30 minutes, Applies=Contractors"
                PassIf   = {
                    param($o)
                    ($o -match 'Name\s*:\s*FGPP-Contractors') -and
                    ($o -match 'MinPasswordLength\s*:\s*16') -and
                    ($o -match 'MaxPasswordAge\s*:\s*90\.00:00:00') -and
                    ($o -match 'ComplexityEnabled\s*:\s*True') -and
                    ($o -match 'LockoutThreshold\s*:\s*3') -and
                    ($o -match 'LockoutDuration\s*:\s*00:30:00') -and
                    ($o -match 'Contractors')
                }
            }

        )
}

# B3.M7 - ADFS: Service is configured under sso.skillsnet.dk
if (Should-Run "B3M7") {
    Test-AspectSteps -Aspect "B3.M7" -Description "ADFS: Service is configured under sso.skillsnet.dk" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "ADFS is running under sso.skillsnet.dk"
                Cmd      = "(Invoke-WebRequest -Uri https://sso.skillsnet.dk/federationmetadata/2007-06/federationmetadata.xml).StatusCode"
                Expected = "200"                 
            }
        )
}

# B3.M8 -- MANUAL

# B3.M9 -- need to think it through

# B3.M10 -- need to think it through

# B3.M11 - DNS: Dynamic updates for domain-joined machines are enabled
if (Should-Run "B3M11") {
    Test-AspectSteps -Aspect "B3.M11" -Description "DNS: Dynamic updates for domain-joined machines are enabled" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "DC: Dynamic updates for domain-joined machines are enabled"
                Cmd      = "(Get-DnsServerZone -Name 'skillsnet.dk').DynamicUpdate"
                Expected = "Secure"                 
            }
        )
}

# B3.M12 - DNS: Delegate skillsdev.dk to DEV-SRV
if (Should-Run "B3M12") {
    Test-AspectSteps -Aspect "B3.M12" -Description "DNS: Delegate skillsdev.dk to DEV-SRV" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "DC: DNS zone delegation for skillsdev.dk"
                Cmd      = "(Get-DnsServerZone -Name 'skillsdev.dk').ZoneType"
                Expected = "Forwarder"                 
            }
        )
}

# B3.M13 - DNS: Use INET as forwarder
if (Should-Run "B3M13") {
    Test-AspectSteps -Aspect "B3.M13" -Description "DNS: Use INET as forwarder" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "DC: DNS use INET as forwarder"
                Cmd      = "(Get-DnsServerForwarder).IPAddress.IPAddressToSTring"
                Expected = "198.51.100.1"                 
            }
        )
}

# B3.M14 - ADCS: CA Common Name is "Skillsnet CA"
if (Should-Run "B3M14") {
    Test-AspectSteps -Aspect "B3.M14" -Description "ADCS: CA Common Name is 'Skillsnet CA'" `
        -DefaultIp "10.1.1.1" -Steps @(
            @{
                Name     = "DC: CA common name is 'Skillsnet CA'"
                Cmd      = "certutil -getconfig"
                Expected = "Config String: DC.skillsnet.dk\Skillsnet CA"
                PassIf = { param($o) $o -match '\bSkillsnet CA\b' }
            }
        )
}
