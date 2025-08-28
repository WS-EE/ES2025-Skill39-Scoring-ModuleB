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

        # Show like your Test-AspectResult style
        if ($actual -eq 1 -or $actual -like " 1") {
            Write-Host "Testing aspect $Aspect failed" -ForegroundColor Red
            Write-Host "Expected: $expected" -ForegroundColor Cyan
            Write-Host "Actual  : ERROR/1" -ForegroundColor White
            Write-Host "Result  : FAIL" -ForegroundColor Red
            continue
        } else {
            Write-Host "Expected:" -NoNewline; Write-Host " $expected" -ForegroundColor Cyan
            Write-Host "Actual  :" -NoNewline; Write-Host " $actual"   -ForegroundColor White
        }

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

