param (
    [Parameter(Mandatory=$true)]
    [string]$CsvFilePath = "C:\Resources\ES2025_TP39_ModuleB_Users_Skillsnet.csv"
)

$CsvData = Import-Csv -Path $CsvFilePath
$Discrepancies = @()
$OuCounts = @{}

foreach ($Row in $CsvData) {
    $SamAccountName = "$($Row.FirstName).$($Row.LastName)"
    
    try {
        $AdUser = Get-ADUser -Filter { SamAccountName -eq $SamAccountName } -Properties DistinguishedName, EmailAddress, GivenName, Surname, Company, City, Department, Title, UserPrincipalName
        
        if ($null -eq $AdUser) {
            $Discrepancies += "User with SAMAccountName $SamAccountName not found in AD."
            continue
        }

        if ($AdUser.GivenName -ne $Row.FirstName) { $Discrepancies += "Mismatched first name for $SamAccountName. Actual: $($AdUser.GivenName), Expected: $($Row.FirstName)" }
        if ($AdUser.Surname -ne $Row.LastName) { $Discrepancies += "Mismatched last name for $SamAccountName. Actual: $($AdUser.Surname), Expected: $($Row.LastName)" }
        if ($AdUser.UserPrincipalName -ne $Row.UserPrincipalName) { $Discrepancies += "Mismatched UPN for $SamAccountName. Actual: $($AdUser.UserPrincipalName), Expected: $($Row.UserPrincipalName)" }
        if ($AdUser.EmailAddress -ne $Row.Email) { $Discrepancies += "Mismatched email for $SamAccountName. Actual: $($AdUser.EmailAddress), Expected: $($Row.Email)" }
        if ($AdUser.Title -ne $Row.JobTitle) { $Discrepancies += "Mismatched job title for $SamAccountName. Actual: $($AdUser.Title), Expected: $($Row.JobTitle)" }
        if ($AdUser.City -ne $Row.City) { $Discrepancies += "Mismatched city for $SamAccountName. Actual: $($AdUser.City), Expected: $($Row.City)" }
        if ($AdUser.Company -ne $Row.Company) { $Discrepancies += "Mismatched company for $SamAccountName. Actual: $($AdUser.Company), Expected: $($Row.Company)" }
        if ($AdUser.Department -ne $Row.Department) { $Discrepancies += "Mismatched department for $SamAccountName. Actual: $($AdUser.Department), Expected: $($Row.Department)" }

        if ($AdUser) {
            $Ou = ($AdUser.DistinguishedName -split ',', 2)[1]
            if ($OuCounts.ContainsKey($Ou)) {
                $OuCounts[$Ou]++
            } else {
                $OuCounts[$Ou] = 1
            }
        }
    }
    catch {
        $Discrepancies += "Error processing $($SamAccountName): $_"
    }
}

$Discrepancies | ForEach-Object { Write-Host $_ }

Write-Host "Users are located in these OUs:"
$OuCounts.Keys | ForEach-Object {
    $Ou = $_
    $Count = $OuCounts[$Ou]
    Write-Host "$($Ou): $Count"
}
