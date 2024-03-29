oh-my-posh init pwsh --config 'C:\Users\EricSiwakoti\AppData\Local\Programs\oh-my-posh\themes\bubblesextra.omp.json' | Invoke-Expression

Import-Module -Name Terminal-Icons
Import-Module -Name PSReadLine
Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineOption -Colors @{ InlinePrediction = ‘#908E8D’}
Set-Alias -Name vim -Value nvim
Set-Alias -Name vi -Value nvim
New-Alias -Name df -Value Get-Volume
New-Alias -Name killall -Value Stop-Process
New-Alias -Name timeout -Value Start-Sleep

function touch {
    New-Item -ItemType File -Name ($args[0])
}

function e {
    Invoke-Item .
}

function which ($command)
{
  Get-Command -Name $command -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue
}

function whichmachine() {
    if ($IsLinux) {
        return "Linux";
    };

    if ($IsOSX) {
        return "macOS";
    }

    return "Windows";
}

function RandomPass {
    <#
    Generates a random password consisting of alphanumeric characters and optional special characters. 
    Also copies the password to your clipboard.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$length = 12,
        [Parameter(Mandatory = $false)]
        [bool]$includeSpecialChars = $true
    )

    # Define character sets
    $alphanumericChars = 48..57 + 65..90 + 97..122
    $specialChars = 33..47 + 58..64 + 91..96 + 123..126

    # Create character pool based on the inclusion of special characters
    $charPool = $alphanumericChars + ($includeSpecialChars -eq $true ? $specialChars : @())

    # Generate the password
    $password = -join ($charPool | Get-Random -Count $length | ForEach-Object { [char]$_ })
    $password | clip

    Write-Output "Your new password is: $password. It has been copied to the clipboard."
}

function grep {
    [CmdletBinding()]
    param(
        [string]$pattern,
        [string]$directory = '.',
        [switch]$ignoreCase,
        [switch]$recursive,
        [switch]$showLineNumbers,
        [switch]$invertMatch,
        [int]$afterContext = 0,
        [int]$beforeContext = 0,
        [int]$context = 0
    )

    # Context control adjustments
    if ($context -gt 0) {
        $beforeContext = $context
        $afterContext = $context
    }

    # Regex options setup
    $regexOptions = 'Compiled'
    if ($ignoreCase) { $regexOptions += ',IgnoreCase' }

    # Create the regex pattern
    $regexPattern = New-Object System.Text.RegularExpressions.Regex($pattern, $regexOptions)

    # Helper function to process each matched line
    function processMatchedLine {
        param($file, $matches, $beforeContext, $afterContext, $invertMatch)

        # Calculate line number boundaries for context
        $startLineNum = if ($matches.LineNumber - $beforeContext -lt 1) { 1 } else { $matches.LineNumber - $beforeContext }
        $endLineNum = if ($matches.LineNumber + $afterContext -gt $file.Length) { $file.Length } else { $matches.LineNumber + $afterContext }

        :begin # Label indicating the start of the block
        foreach ($line in $file) {
            $lineNum++ # Increment line number counter

            # Output lines within the context range with optional line numbers
            if ($lineNum -ge $startLineNum -and $lineNum -le $endLineNum) {
                Write-Output ("{0}:{1}:{2}" -f $file.FullName, $($lineNum), ($line.Trim()))
            }

            if ($lineNum -gt $endLineNum) { break begin } # Break out of the loop if we've reached the end of the context range
        }
    }

    # Search and process files
    Get-ChildItem -Path $directory -Include '*.*' -File -Recurse:$recursive -ErrorAction Stop | ForEach-Object {
        try {
            $content = Get-Content -Path $_.FullName -ErrorAction Stop
            switch -Regex ($content) {
                $regexPattern {
                    processMatchedLine $_ $matches $beforeContext $afterContext $invertMatch
                } default {
                    # Handle non-matching lines here if necessary
                }
            }
        } catch {
            Write-Output "Error reading file: $_.FullName. Skipping..."
        }
    }
}

function wc {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    if (-not (Test-Path -Path $FilePath)) {
        Write-Error "The specified file was not found."
        return
    }

    try {
        # Use .NET method to read the file more efficiently
        $fileContent = [System.IO.File]::ReadAllText($FilePath)

        # Using regex to find matches
        $lineCount = [regex]::Matches($fileContent, "`n").Count
        $wordCount = [regex]::Matches($fileContent, "\b\w+\b").Count
        $byteCount = [System.Text.Encoding]::UTF8.GetByteCount($fileContent)
        $characterCount = $fileContent.Length

        # Create a custom object to hold the statistics
        $fileStats = New-Object -TypeName PSObject
        $fileStats | Add-Member -MemberType NoteProperty -Name FilePath -Value $FilePath
        $fileStats | Add-Member -MemberType NoteProperty -Name LineCount -Value $lineCount
        $fileStats | Add-Member -MemberType NoteProperty -Name WordCount -Value $wordCount
        $fileStats | Add-Member -MemberType NoteProperty -Name ByteCount -Value $byteCount
        $fileStats | Add-Member -MemberType NoteProperty -Name CharacterCount -Value $characterCount

        Write-Output $fileStats
    }
    catch {
        Write-Error "An error occurred while processing the file: $_"
    }
}

function sed {
    param (
        [Parameter(Mandatory)]
        [string]$Pattern,
        [Parameter(Mandatory)]
        [string]$Replacement,
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Load file content
    try {
        $content = Get-Content $Path -ErrorAction Stop
    } catch {
        Write-Host "Error occurred while loading file content: $_"
        return
    }

    # Replace content
    try {
        $newContent = $content -replace $Pattern, $Replacement
    } catch {
        Write-Host "Error occurred while replacing content: $_"
        return
    }

    # Save new content
    try {
        Set-Content -Path $Path -Value $newContent -ErrorAction Stop
        Write-Host "SED operation succeeded. The modified file is located at '$Path'."
    } catch {
        Write-Host "Error occurred while saving new content: $_"
    }
}

function Chown-Pwsh {
    <#
    .SYNOPSIS
        Changes the owner of files or directories.

    .DESCRIPTION
        Chown-Pwsh changes the owner of files or directories. It is similar to the Unix chown command.

    .PARAMETER user
        The new owner of the files or directories.

    .PARAMETER path
        An array of paths to files or directories to change ownership.

    .EXAMPLE
        Chown-Pwsh -user 'NewOwner' -path @('C:\Path\To\File.txt', 'C:\Path\To\Directory')

    .NOTES
        If user or path is empty or contains only whitespace, an error will be thrown.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$user,

        [Parameter(Mandatory=$true)]
        [string[]]$path
    )

    # Validate input
    if ($user -eq "" -or $path -contains "" -or $path -contains $null) {
        Write-Error "User or path cannot be empty or contain only whitespace."
        return
    }

    # Loop through each path and change ownership
    foreach ($p in $path) {
        try {
            $currentACL = Get-Acl -Path $p -ErrorAction Stop

            $newOwner = New-Object System.Security.Principal.NTAccount($user)

            $currentACL.SetOwner($newOwner)

            Set-Acl -Path $p -AclObject $currentACL -Confirm:$false -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to change ownership of '$p'. $_"
        }
    }
}
Set-Alias -Name chown -Value Chown-Pwsh

function wget($url, $outFile) {
    # Invoke web request and obtain response headers and stream
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Error "Error while making the web request: $_"
        return
    }

    # Calculate content length and initialize streams
    $contentLength = [int]$response.Headers.'Content-Length'
    $bufferSize = 1024
    $responseStream = $response.RawContentStream
    $fileStream = [System.IO.File]::Create($outFile)
    $bytesRead = 0
    $buffer = New-Object byte[] $bufferSize

    # Download the file and show progress
    try {
        while (($bytesRead = $responseStream.Read($buffer, 0, $bufferSize)) -gt 0) {
            $fileStream.Write($buffer, 0, $bytesRead)
            $totalBytesRead += $bytesRead
            Write-Progress -Activity "Downloading file" -Status "Bytes downloaded: $totalBytesRead" -PercentComplete (($totalBytesRead / $contentLength) * 100)
        }
    } catch {
        Write-Error "Error while downloading the file: $_"
        return
    } finally {
        # Close the streams and clean up
        $fileStream.Close()
        $responseStream.Close()
    }
}

function Get-WhoIs {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$domainOrIp
    )

    # Validate domain or IP
    $isDomain = $domainOrIp -match '^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
    $isIp = $domainOrIp -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    if (-not ($isDomain -or $isIp)) {
        Write-Error "Invalid domain or IP address"
        return
    }

    # Set the appropriate whois server
    $server = if ($isDomain) {
        "whois.internic.net"
    } else {
        "whois.arin.net"
    }

    try {
        # Create a TCP client and connect to the server
        $tcpClient = [System.Net.Sockets.TcpClient]::new($server, 43)
        $stream = $tcpClient.GetStream()
        $writer = [System.IO.StreamWriter]::new($stream)
        $buffer = [byte[]]::new(1024)
        $encoding = [System.Text.ASCIIEncoding]::new()

        # Send the query and flush the stream
        $writer.WriteLine("$domainOrIp")
        $writer.Flush()

        # Read the response and convert it to a string
        $data = ""
        while (($count = $stream.Read($buffer, 0, 1024)) -gt 0) {
            $data += $encoding.GetString($buffer, 0, $count)
        }

        # Close the TCP client
        $tcpClient.Close()

        Write-Output $data
    } catch {
        Write-Error "Failed to retrieve whois data"
    }
}
New-Alias -Name whois -Value Get-WhoIs
