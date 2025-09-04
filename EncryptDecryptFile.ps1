param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [Parameter(Mandatory=$true)]
    [string]$Password,

    [Parameter(Mandatory=$true)]
    [ValidateSet("encrypt", "decrypt")]
    [string]$Action
)

function Create-AesKey ($Password) {
    # Convert the password to a byte array
    $PasswordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    
    # Create a SHA256 hash from the password bytes
    $Sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    
    # Return the AES key
    return $Sha256.ComputeHash($PasswordBytes)
}

function Encrypt-File ($FilePath, $Key) {
    # Check if the file exists
    if (Test-Path $FilePath) {
        # Define the output file name for the encrypted file
        $OutputFile = $FilePath + ".encrypted"

        # Initialize AES encryption
        $Aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $Aes.Key = $Key
        $Aes.IV = $Key[0..15]

        # Create the encrypted file stream
        $FsCrypt = New-Object System.IO.FileStream $OutputFile, "Create"
        $CryptoStream = New-Object System.Security.Cryptography.CryptoStream $FsCrypt, $Aes.CreateEncryptor(), "Write"

        # Read the input file as a byte stream
        $FsIn = New-Object System.IO.FileStream $FilePath, "Open"

        # Copy the content to the encrypted stream
        $FsIn.CopyTo($CryptoStream)

        # Close all streams
        $FsIn.Close()
        $CryptoStream.Close()
        $FsCrypt.Close()
    } else {
        Write-Host "File $FilePath does not exist."
    }
}

function Decrypt-File ($FilePath, $Key) {
    # Check if the file exists
    if (Test-Path $FilePath) {
        # Extract the original file extension
        $OriginalExtension = ($FilePath -replace ".*\.encrypted", "")

        # Change the output file extension back to the original
        $OutputFile = [IO.Path]::ChangeExtension($FilePath, $OriginalExtension)

        # Initialize AES decryption
        $Aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $Aes.Key = $Key
        $Aes.IV = $Key[0..15]

        # Create the decrypted file stream
        $FsCrypt = New-Object System.IO.FileStream $FilePath, "Open"
        $CryptoStream = New-Object System.Security.Cryptography.CryptoStream $FsCrypt, $Aes.CreateDecryptor(), "Read"

        # Create the output file stream for the decrypted file
        $FsOut = New-Object System.IO.FileStream $OutputFile, "Create"

        # Copy the content to the decrypted stream
        $CryptoStream.CopyTo($FsOut)

        # Close all streams
        $FsOut.Close()
        $CryptoStream.Close()
        $FsCrypt.Close()
    } else {
        Write-Host "File $FilePath does not exist."
    }
}

# Generate the AES key based on the given password
$Key = Create-AesKey $Password

# Perform encryption or decryption based on the selected action
if ($Action -eq "encrypt") {
    Encrypt-File -FilePath $FilePath -Key $Key
} elseif ($Action -eq "decrypt") {
    Decrypt-File -FilePath $FilePath -Key $Key
}
