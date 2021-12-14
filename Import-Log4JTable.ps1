<#
.SYNOPSIS
    Installs and populates a table in a MySQL with a list of potential Log4Shell affected software.
.EXAMPLE
Gets a credential object to authenticate with MySQL and imports the data into the 'labtech' database with the table name 'plugin_proval_log4jsoftwarelist'
    PS C:\> $cred = Get-Credential
    PS C:\> Import-Log4JTable.ps1 -Credential $cred
.EXAMPLE
Creates a credential object to authenticate with MySQL and imports the data into the 'labtech2' database with the table name 'plugin_mytable_log4j'
    PS C:\> $cred = New-Object System.Management.Automation.PSCredential("MyUsername", (ConvertTo-SecureString -String "p@ssw0Rd" -AsPlainText -Force))
    PS C:\> Import-Log4JTable.ps1 -Credential $cred -Database labtech2 -TableName plugin_mytable_log4j
.PARAMETER Credential
    Credential object to authenticate with MySQL.
.PARAMETER Database
    The database to import the data into.
.PARAMETER TableName
    The table to import the data into.
.OUTPUTS
    .\Import-Log4JTable-log.txt
    .\Import-Log4JTable-data.txt
    .\Import-Log4JTable-error.txt
    .\log4jquery.sql
.NOTES
    This script uses mysql.exe and as such must be run directly on the MySQL server, as currently no remote target parameters are implemented.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][pscredential]$Credential,
    [Parameter(Mandatory=$false)][string]$Database = "labtech",
    [Parameter(Mandatory=$false)][string]$TableName = "plugin_proval_log4jsoftwarelist"
)

### Init ###
$logPath = $null
$dataPath = $null
$errorPath = $null
$workingPath = $null
$scriptTitle = $null
$isElevated = $false

function Write-LogHelper {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ParameterSetName="String")]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter(Mandatory=$true, ParameterSetName="String")]
        [string]$Type
    )
    $formattedLog = "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))  $($Type.PadRight(8)) $Text"
    switch ($Type) {
        "LOG" { 
            Write-Host -Object $formattedLog
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "INIT" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkBlue
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "WARN" {
            Write-Host -Object $formattedLog -ForegroundColor Black -BackgroundColor DarkYellow
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "ERROR" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkRed
            Add-Content -Path $script:logPath -Value $formattedLog
            Add-Content -Path $script:errorPath -Value $formattedLog
        }
        "SUCCESS" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkGreen
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "DATA" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor Blue
            Add-Content -Path $script:logPath -Value $formattedLog
            Add-Content -Path $script:dataPath -Value $Text
        }
        Default {
            Write-Host -Object $formattedLog
            Add-Content -Path $script:logPath -Value $formattedLog
        }
    }
}
function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to a log file, the console, or both.
    .EXAMPLE
        PS C:\> Write-Log -Text "An error occurred." -Type ERROR
        This will write an error to the console, the log file, and the error log file.
    .PARAMETER Text
        The message to pass to the log.
    .PARAMETER Type
        The type of log message to pass in. The options are:
        LOG     - Outputs to the log file and console.
        WARN    - Outputs to the log file and console.
        ERROR   - Outputs to the log file, error file, and console.
        SUCCESS - Outputs to the log file and console.
        DATA    - Outputs to the log file, data file, and console.
        INIT    - Outputs to the log file and console.
    .NOTES
        This function is dependant on being run within a script. This will not work run directly from the console.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position = 0, ParameterSetName="String")]
        [AllowEmptyString()][Alias("Message")]
        [string]$Text,
        [Parameter(Mandatory=$true, Position = 0, ParameterSetName="StringArray")]
        [AllowEmptyString()]
        [string[]]$StringArray,
        [Parameter(Mandatory=$false, Position = 1, ParameterSetName="String")]
        [Parameter(Mandatory=$false, Position = 1, ParameterSetName="StringArray")]
        [string]$Type = "LOG"
    )
    if($script:PSCommandPath -eq '') {
        Write-Error -Message "This function cannot be run directly from a terminal." -Category InvalidOperation
        return
    }
    if($null -eq $script:logPath) {
        Set-Environment
    }

    if($StringArray) {
        foreach($logItem in $StringArray) {
            Write-LogHelper -Text $logItem -Type $Type
        }
    } elseif($Text) {
        Write-LogHelper -Text $Text -Type $Type
    }
}
Register-ArgumentCompleter -CommandName Write-Log -ParameterName Type -ScriptBlock {"LOG","WARN","ERROR","SUCCESS","DATA","INIT"}
function Set-Environment {
    <#
    .SYNOPSIS
        Sets ProVal standard variables for logging and error handling.
    .EXAMPLE
        PS C:\> Set-Environment
    #>
    $scriptObject = Get-Item -Path $script:PSCommandPath
    $script:workingPath = $($scriptObject.DirectoryName)
    $script:logPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-log.txt"
    $script:dataPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-data.txt"
    $script:errorPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-error.txt"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    Remove-Item -Path $script:dataPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $script:errorPath -Force -ErrorAction SilentlyContinue
    $script:scriptTitle = $scriptObject.BaseName
    Write-Log -Text "-----------------------------------------------" -Type INIT
    Write-Log -Text $scriptTitle -Type INIT
    Write-Log -Text "System: $($env:COMPUTERNAME)" -Type INIT
    Write-Log -Text "User: $($env:USERNAME)" -Type INIT
    Write-Log -Text "OS Bitness: $($env:PROCESSOR_ARCHITECTURE)" -Type INIT
    Write-Log -Text "PowerShell Bitness: $(if([Environment]::Is64BitProcess) {64} else {32})" -Type INIT
    Write-Log -Text "PowerShell Version: $(Get-Host | Select-Object -ExpandProperty Version | Select-Object -ExpandProperty Major)" -Type INIT
    Write-Log -Text "-----------------------------------------------" -Type INIT
}
Set-Environment

### Process ###
class Software {
    [string]$Supplier
    [string]$Product
    [string]$Version
    [string]$Status
    [string]$Notes
    [string]$Links

    [string]ToString() {
        return "$($this.Supplier) - $($this.Product) - $($this.Version) - $($this.Status) - $($this.Notes) - $($this.Links)"
    }

    [string]GetSQLValueString() {
        return "( '$(($this.Supplier -replace "'","\'"))', '$(($this.Product -replace "'","\'"))', '$(($this.Version -replace "'","\'"))', '$(($this.Status -replace "'","\'"))', '$(($this.Notes -replace "'","\'"))', '$(($this.Links -replace "'","\'"))' )"
    }
}
if(Test-Path -Path "$($env:ProgramFiles)\MySQL") {
    $mySqlEXEPath = Get-ChildItem -Path "$($env:ProgramFiles)\MySQL" -Filter "mysql.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName
}
if(-not $mySqlEXEPath) {
    Write-Log -Text "Unable to determine mysql.exe location. Exiting." -Type ERROR
    return 1
}
[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
$raw = (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/NCSC-NL/log4shell/main/software/README.md")
$rawTable = $raw.Substring($raw.IndexOf("| Supplier")) -split "`n"
$rawTable = $rawTable[2..($rawTable.length - 1)]
$softwareList = @()
foreach($entry in $rawTable) {
    if($entry -match "Supplier.*\|.*Product|:-+:") {continue}
    $values = $entry -split "\|"
    if([String]::IsNullOrWhiteSpace($values[1])) {continue}
    $softwareEntry = [Software]::new()
    $softwareEntry.Supplier = $values[1].Trim()
    $softwareEntry.Product = $values[2].Trim()
    $softwareEntry.Version = $values[3].Trim()
    $softwareEntry.Status = $values[4].Trim()
    $softwareEntry.Notes = $values[5].Trim()
    $softwareEntry.Links = $values[6].Trim()
    $softwareList += $softwareEntry
}
$sqlQuery = "
CREATE TABLE IF NOT EXISTS $Database.$TableName(  
  Supplier VARCHAR(255),
  Product VARCHAR(255),
  Version VARCHAR(1024),
  Status VARCHAR(1024),
  Notes VARCHAR(1024),
  Links VARCHAR(1024),
  PRIMARY KEY (`Supplier`, `Product`)
);
REPLACE INTO $TableName VALUES "
foreach($software in $softwareList) {
    $sqlQuery += "$($software.GetSQLValueString()),"
}
$sqlQuery = $sqlQuery.TrimEnd(',')
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
$sqlFilePath = "$($workingPath)\log4jquery.sql"
[System.IO.File]::WriteAllLines($sqlFilePath, $sqlQuery, $Utf8NoBomEncoding)

cmd /c """$mySqlEXEPath"" --user=""$($Credential.UserName)"" --password=""$([System.Net.NetworkCredential]::new('', $Credential.Password).Password)"" $database < ""$sqlFilePath"""
Write-Log -Text "SQL query successfully executed." -Type DATA
