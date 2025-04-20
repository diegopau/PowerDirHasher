param (
    [string]$Path = ""  # Path parameter that can be provided via drag-and-drop (directory or .hashtask file)
)

# ======================================================================
# PowerDirHasher - Generates multiple hash types for all files
# in a directory structure with minimal disk activity and memory usage
# Copyright (c) 2025 Diego Ocampo Pérez
# MIT License
# ======================================================================

# Script version - update this when making changes
$scriptVersion = "0.5.9"

# Track script success/failure
$global:scriptFailed = $false


# ======================================================================
# Helper functions
# ======================================================================

function Get-NormalizedPath {
    param (
        [string]$Path
    )
    
    if ([string]::IsNullOrEmpty($Path)) {
        return $Path
    }
    
    # Strip \\?\ prefix if present
    if ($Path.StartsWith("\\?\")) {
        return $Path.Substring(4)
    }
    
    return $Path
}

function Get-LongPath {
    param (
        [string]$Path
    )
    
    if ([string]::IsNullOrEmpty($Path)) {
        return $Path
    }
    
    if ($Path.StartsWith("\\?\")) {
        return $Path
    }
    
    return "\\?\$Path"
}

# Function to check if long path support is enabled
function Check-LongPathsSupport {
    $script:longPathsEnabled = $false
    
    if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem') {
        $regValue = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -ErrorAction SilentlyContinue
        if ($null -ne $regValue -and $regValue.LongPathsEnabled -eq 1) {
            $script:longPathsEnabled = $true
        }
    }
    
    if (-not $script:longPathsEnabled) {
        $message = "Long path support is not enabled in Windows. Paths exceeding 260 characters may fail."
        
        if ($script:generalSettings.IsLongPathsEnabledMandatory) {
            Write-Host $message -ForegroundColor Red
            Write-Host "This operation requires long path support to be enabled. Exiting..." -ForegroundColor Red
            Write-Host "To enable Long Path support in Windows, run the following command in an elevated PowerShell:" -ForegroundColor Yellow
            Write-Host "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1" -ForegroundColor Yellow
            Write-Host "Then restart your computer for the changes to take effect." -ForegroundColor Yellow
            exit
        } else {
            Write-Host $message -ForegroundColor Yellow
            Write-Host "To enable Long Path support in Windows, run the following command in an elevated PowerShell:" -ForegroundColor Yellow
            Write-Host "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1" -ForegroundColor Yellow
            Write-Host "Then restart your computer for the changes to take effect." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Long path support is enabled." -ForegroundColor Green
    }
    
    return $script:longPathsEnabled
}


# Function to read settings from INI file
function Read-IniFile {
    param (
        [string]$FilePath
    )
    
    $ini = @{}
    $section = "default"
    $ini[$section] = @{}
    
    switch -regex -file $FilePath {
        "^\[(.+)\]" {
            $section = $matches[1].Trim()
            $ini[$section] = @{}
        }
        "(.+)=(.+)" {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            
            # Remove quotes if present
            if ($value.StartsWith('"') -and $value.EndsWith('"')) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            
            # Add to section
            $ini[$section][$name] = $value
        }
    }
    
    return $ini
}

# Function to initialize settings
function Initialize-Settings {
    # Get the directory where the script is located, with fallback options
    $scriptDir = if ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    } elseif ($PSScriptRoot) {
        $PSScriptRoot
    } else {
        # Last resort fallback to current directory
        (Get-Location).Path
    }
    $iniFilePath = Join-Path -Path $scriptDir -ChildPath "settings.ini"
    
    if (Test-Path $iniFilePath) {
        $script:settings = Read-IniFile -FilePath $iniFilePath
        
        # Parse general settings
        $script:generalSettings = @{
            IsLongPathsEnabledMandatory = $true
            SetHashFilesReadOnly = $true  # Default to true if not specified
        }

        # Set script-level variables from INI settings
        $script:logFolderPath = $script:settings["paths"]["haslog_folder"]
        $script:hashFolderName = $script:settings["paths"]["subfolder_for_folder_hashes"]
        $script:fileHashFolderName = $script:settings["paths"]["subfolder_for_single_file_hashes"]
        
        # Parse algorithms
        $algosString = $script:settings["hash files"]["algos"]
        $script:algorithms = $algosString -split ',' | ForEach-Object { $_.Trim() }
        
        # Parse logging settings
        $script:logSettings = @{
            ShowSubfolderCurrentlyBeingProcessed = $true
            ShowProcessedFileCountEach = 100
            ShowInLog = @{}
            ShowInTerminal = @{}
        }
        
        # Get boolean value from string
        function Get-BooleanValue {
            param([string]$value)
            return $value -eq "true"
        }

        $generalSection = $script:settings["general"]
        if ($generalSection) {
            # Process general settings
            if ($generalSection.ContainsKey("is_long_paths_enabled_mandatory")) {
                $script:generalSettings.IsLongPathsEnabledMandatory = Get-BooleanValue $generalSection["is_long_paths_enabled_mandatory"]
            } else {
                Write-Host "Error: is_long_paths_enabled_mandatory setting not found in settings.ini. Applying defaults." -ForegroundColor Red
            }
            # Add read-only setting
            if ($generalSection.ContainsKey("set_hash_files_read_only")) {
                $script:generalSettings.SetHashFilesReadOnly = Get-BooleanValue $generalSection["set_hash_files_read_only"]
            } else{
                Write-Host "Error: set_hash_files_read_only setting not found in settings.ini. Applying defaults." -ForegroundColor Red
            }
        }

        # Process logging settings
        $logsSection = $script:settings["logs and terminal output"]
        if ($logsSection) {
            # Process process indicators
            if ($logsSection["show_subfolder_currently_being_processed"]){
                $script:logSettings.ShowSubfolderCurrentlyBeingProcessed = Get-BooleanValue $logsSection["show_subfolder_currently_being_processed"]
            } else {
                Write-Host "Error: show_subfolder_currently_being_processed setting not found in settings.ini. Applying defaults." -ForegroundColor Red
            }
            
            # Process file count display interval
            if ($logsSection["show_processed_file_count_each"]) {
                $script:logSettings.ShowProcessedFileCountEach = [int]$logsSection["show_processed_file_count_each"]
            } else {
                Write-Host "Error: show_processed_file_count_each setting not found in settings.ini. Applying defaults." -ForegroundColor Red
            }
            
            # Process status logging settings
            $statuses = @(
                "identical", "skipped", "added", "excluded", "reincluded", 
                "touched", "modified_date_size", "modified_only_date", 
                "deleted", "readded"
            )
            
            foreach ($status in $statuses) {
                $logKey = "show_${status}_in_log"
                $terminalKey = "show_${status}_in_terminal"
                
                if ($logsSection.ContainsKey($logKey)) {
                    $script:logSettings.ShowInLog[$status] = Get-BooleanValue $logsSection[$logKey]
                } else {
                    Write-Host "Error: some logging settings not found in settings.ini. Applying defaults." -ForegroundColor Red
                    $script:logSettings.ShowInLog[$status] = $true
                }
                
                if ($logsSection.ContainsKey($terminalKey)) {
                    $script:logSettings.ShowInTerminal[$status] = Get-BooleanValue $logsSection[$terminalKey]
                } else {
                    Write-Host "Error: some logging settings not found in settings.ini. Applying defaults." -ForegroundColor Red
                    $script:logSettings.ShowInTerminal[$status] = $true
                }
            }
            
            # Special handling for excluded
            if ($logsSection["show_excluded_in_log"] -eq "none") {
                $script:logSettings.ShowInLog["excluded"] = $false
            } elseif ($logsSection["show_excluded_in_log"] -eq "previously_added") {
                $script:logSettings.ShowInLog["excluded"] = "previously_added"
            } elseif ($logsSection["show_excluded_in_log"] -eq "all") {
                $script:logSettings.ShowInLog["excluded"] = "all"
            } else {
                # Default if not specified or invalid value
                Write-Host "Error: some logging settings not found in settings.ini. Applying defaults." -ForegroundColor Red
                $script:logSettings.ShowInLog["excluded"] = "previously_added"
            }

            if ($logsSection["show_excluded_in_terminal"] -eq "none") {
                $script:logSettings.ShowInTerminal["excluded"] = $false
            } elseif ($logsSection["show_excluded_in_terminal"] -eq "previously_added") {
                $script:logSettings.ShowInTerminal["excluded"] = "previously_added"
            } elseif ($logsSection["show_excluded_in_terminal"] -eq "all") {
                $script:logSettings.ShowInTerminal["excluded"] = "all"
            } else {
                # Default if not specified or invalid value
                Write-Host "Error: some logging settings not found in settings.ini. Applying defaults." -ForegroundColor Red
                $script:logSettings.ShowInTerminal["excluded"] = "previously_added"
            }
        } else {
            Write-Host "Error: logs and terminal output section not found in settings.ini." -ForegroundColor Red
            exit 1
        }
        
        Write-Host "Settings loaded from: $iniFilePath" -ForegroundColor Green
    }
    else {
        # Use defaults if INI file not found
        Write-Host "Error: settings.ini not found." -ForegroundColor Red
        # Exit with error code
        exit 1
    }
}

# Function to determine if a status should be logged or displayed
function Should-LogStatus {
    param (
        [string]$Status,
        [string]$Location, # "log" or "terminal"
        [bool]$IsPreviouslyAdded = $false
    )
    
    # Always log/show critical statuses
    $criticalStatuses = @(
        "ALERT_MODIFIED_ONLY_SIZE", "ALERT_CORRUPTED", "ALERT_COLLISION", 
        "ALERT_HASH_INCONSISTENCY", "ADDED_ERROR", "ADDED_FIXED"
    )
    
    if ($Status -in $criticalStatuses) {
        return $true
    }
    
    # Map status to settings key
    $statusKey = $Status.ToLower()
    $statusKey = $statusKey -replace "^added$", "added"
    $statusKey = $statusKey -replace "^modified_date_size$", "modified_date_size"
    $statusKey = $statusKey -replace "^modified_only_date$", "modified_only_date"
    $statusKey = $statusKey -replace "^deleted$", "deleted"
    $statusKey = $statusKey -replace "^identical$", "identical"
    $statusKey = $statusKey -replace "^skipped$", "skipped"
    $statusKey = $statusKey -replace "^excluded$", "excluded"
    $statusKey = $statusKey -replace "^reincluded$", "reincluded"
    $statusKey = $statusKey -replace "^touched$", "touched"
    $statusKey = $statusKey -replace "^readded$", "readded"
    
    # Get the appropriate settings collection
    $settingsKey = if ($Location -eq "log") { "ShowInLog" } else { "ShowInTerminal" }
    
    # If status not in settings, default to true
    if (-not $script:logSettings[$settingsKey].ContainsKey($statusKey)) {
        return $true
    }
    
    # Handle special case for excluded
    if ($statusKey -eq "excluded" -and $script:logSettings[$settingsKey][$statusKey] -eq "previously_added") {
        return $IsPreviouslyAdded
    }
    
    # Return the setting value
    return $script:logSettings[$settingsKey][$statusKey]
}

# Function to check if algorithms have changed for a folder
function Test-AlgorithmsChanged {
    param (
        [string]$HashesFilePath,
        [string[]]$CurrentAlgorithms
    )
    
    try {
        # Read the CSV file, getting only comment lines that start with #
        $longPath = Get-LongPath -Path $HashesFilePath
        $content = Get-Content -LiteralPath $longPath | Where-Object { $_.StartsWith("#") }
        
        # Find the line with algorithms - only support new format with colon
        $algoLine = $content | Where-Object { $_ -match "# Hash algorithms used:" }
        
        if (-not $algoLine) {
            return $true  # No matching line found, treat as changed
        }
        
        # Extract algorithms - only supporting new format with colon
        if ($algoLine -match "# Hash algorithms used: (.+)$") {
            $usedAlgos = $matches[1].Trim() -split '\s+'
        } 
        else {
            # Couldn't parse properly - should never happen with the above check
            Write-Log -Message "Warning: Could not parse algorithm line: $algoLine" -LogFilePath $null -ForegroundColor Yellow
            return $true  # Treat as changed
        }
        
        # Normalize both arrays for comparison
        $normalizedUsedAlgos = $usedAlgos | Sort-Object
        $normalizedCurrentAlgos = $CurrentAlgorithms | Sort-Object
        
        # If counts don't match, algorithms changed
        if ($normalizedUsedAlgos.Count -ne $normalizedCurrentAlgos.Count) {
            return $true
        }
        
        # Compare each algorithm
        for ($i = 0; $i -lt $normalizedUsedAlgos.Count; $i++) {
            if ($normalizedUsedAlgos[$i] -ne $normalizedCurrentAlgos[$i]) {
                return $true  # Found a difference
            }
        }
        
        return $false  # No differences found
    }
    catch {
        Write-Log -Message "Error checking algorithm changes: $_" -LogFilePath $null -ForegroundColor Red
        return $true  # Assume change in case of error to be safe
    }
}

# Function to parse task line with exclusions
function Parse-ItemLine {
    param (
        [string]$ItemLine
    )
    
    # Initialize result
    $itemInfo = @{
        Path = $null
        Exclusions = @()
    }
    
    # Use regular expression to parse the line with quoted items
    $matchResults = [regex]::Matches($ItemLine, '("[^"]*")')
    
    if ($matchResults.Count -ge 1) {
        # First match is the path
        $pathWithQuotes = $matchResults[0].Value
        $path = $pathWithQuotes.Substring(1, $pathWithQuotes.Length - 2)  # Remove quotes
        $itemInfo.Path = $path
        
        # Process exclusions (if any)
        for ($i = 1; $i -lt $matchResults.Count; $i++) {
            $exclusionWithQuotes = $matchResults[$i].Value
            
            # Check if it starts with a dash
            $dashPos = $ItemLine.IndexOf("-" + $exclusionWithQuotes)
            if ($dashPos -ge 0) {
                $exclusion = $exclusionWithQuotes.Substring(1, $exclusionWithQuotes.Length - 2)  # Remove quotes
                $itemInfo.Exclusions += $exclusion
            }
        }
    }
    
    return $itemInfo
}

# Function to validate exclusion patterns
function Validate-ExclusionPatterns {
    param (
        [string[]]$Exclusions
    )
    
    $invalidExclusions = @()
    
    foreach ($exclusion in $Exclusions) {
        # Count asterisks in the pattern
        $asteriskCount = ($exclusion.ToCharArray() | Where-Object { $_ -eq '*' } | Measure-Object).Count
        
        if ($asteriskCount -gt 1) {
            $invalidExclusions += "Exclusion '$exclusion' contains more than one asterisk (*)"
            continue
        }
        
        # First check if it's a folder pattern (ends with \)
        $isFolder = $exclusion.EndsWith('\')
        
        if ($isFolder) {
            # Folder-specific validation if needed
            # Currently, no additional validation required for folders
        }
        else {
            # If not a folder, it must be a file with an extension
            if (-not $exclusion.Contains('.')) {
                $invalidExclusions += "Exclusion '$exclusion' is not a valid file (missing extension) or folder (must end with \)"
                continue
            }
            
            # Check if the extension has an asterisk
            $extension = $exclusion.Substring($exclusion.LastIndexOf('.'))
            if ($extension.Contains('*')) {
                $invalidExclusions += "Exclusion '$exclusion' has an asterisk in the extension, this is not allowed."
                continue
            }
            
            # Check if file has an extension
            if ($extension -eq '.') {
                $invalidExclusions += "Exclusion '$exclusion' is a file without an extension, this is not allowed."
                continue
            }
        }
    }
    
    return $invalidExclusions
}

# Function to check if a file or folder matches any exclusion pattern
function Test-ExclusionMatch {
    param (
        [string]$Path,
        [string[]]$Exclusions
    )
    
    if ($Exclusions.Count -eq 0) {
        return $false
    }
    
    # Get just the file name
    $fileName = [System.IO.Path]::GetFileName($Path)
    
    # Get directory path
    $directoryPath = [System.IO.Path]::GetDirectoryName($Path)
    
    # Normalize path for comparison
    if ($directoryPath.StartsWith("\\?\")) {
        $directoryPath = $directoryPath.Substring(4)
    }
    
    # Get relative path if we have a global base path
    $relativePath = $directoryPath
    if ($null -ne $script:hashTaskBasePath) {
        # Check if the path starts with the base path
        if ($directoryPath.StartsWith($script:hashTaskBasePath, [StringComparison]::OrdinalIgnoreCase)) {
            # Extract only the portion after the base path
            $relativePath = $directoryPath.Substring($script:hashTaskBasePath.Length)
        } else {
            Write-Host "ERROR: the base path of the hashtask file does not match the path of the file being processed" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "ERROR: the base path of the hashtask file is not properly set" -ForegroundColor Red
        exit 1
    }
    
    foreach ($exclusion in $Exclusions) {
        $exclusionIsFolder = $exclusion.EndsWith('\')
        
        if ($exclusionIsFolder) {
            # For folder exclusions, check if this folder appears in the path
            # Remove trailing backslash from exclusion for comparison
            $folderName = $exclusion.TrimEnd('\')
            
            # Check specifically for this folder as a complete segment in the path
            $pathParts = $relativePath.Split([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            
            if ($folderName.Contains('*')) {
                # Handle wildcard pattern
                $wildcardIndex = $folderName.IndexOf('*')
                $patternStart = $folderName.Substring(0, $wildcardIndex)
                $patternEnd = $folderName.Substring($wildcardIndex + 1)
                
                foreach ($part in $pathParts) {
                    if ($part -and 
                        (($patternStart -eq "" -or $part.StartsWith($patternStart)) -and 
                         ($patternEnd -eq "" -or $part.EndsWith($patternEnd)))) {
                        return $true
                    }
                }
            }
            else {
                # Exact folder name match
                if ($pathParts -contains $folderName) {
                    return $true
                }
            }
        }
        else {
            # File exclusion - compare with file name only
            if ($exclusion.Contains('*')) {
                # Handle wildcard pattern
                $wildcardIndex = $exclusion.IndexOf('*')
                $patternStart = $exclusion.Substring(0, $wildcardIndex)
                $patternEnd = $exclusion.Substring($wildcardIndex + 1)
                
                if (($patternStart -eq "" -or $fileName.StartsWith($patternStart)) -and 
                    ($patternEnd -eq "" -or $fileName.EndsWith($patternEnd))) {
                    return $true
                }
            }
            else {
                # Exact file name match
                if ($fileName -eq $exclusion) {
                    return $true
                }
            }
        }
    }
    
    return $false
}

# Define function to get hash algorithm using recommended pattern (non-obsolete)
function Get-HashAlgorithm {
    param (
        [string]$Algorithm
    )
    
    switch ($Algorithm) {
        "MD5" { return [System.Security.Cryptography.MD5]::Create() }
        "SHA1" { return [System.Security.Cryptography.SHA1]::Create() }
        "SHA256" { return [System.Security.Cryptography.SHA256]::Create() }
        "SHA3_256" { return [System.Security.Cryptography.SHA3_256]::Create() }
        "SHA3_384" { return [System.Security.Cryptography.SHA3_384]::Create() }
        "SHA3_512" { return [System.Security.Cryptography.SHA3_512]::Create() }
        "SHA384" { return [System.Security.Cryptography.SHA384]::Create() }
        "SHA512" { return [System.Security.Cryptography.SHA512]::Create() }
        default { throw "Unsupported hash algorithm: $Algorithm" }
    }
}

# Define function to calculate multiple hash types in a single file read
function Get-MultipleFileHashes {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Algorithms = @("MD5", "SHA512")
    )

    try {
        # Create a dictionary to hold all the hash algorithm instances
        $hashers = @{}
        foreach ($algo in $Algorithms) {
            $hashers[$algo] = Get-HashAlgorithm -Algorithm $algo
        }

        $longPath = Get-LongPath -Path $FilePath

        # Open the file once and read it in chunks
        $stream = [System.IO.File]::OpenRead($longPath)
        # 4KB buffer for reading matching NTFS default cluster size and Windows default memory page size
        $buffer = New-Object byte[] 4096
        $bytesRead = 0

        # Process the file in chunks to handle files of any size
        do {
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -gt 0) {
                # Update all hashers with the same chunk of data
                foreach ($algo in $Algorithms) {
                    $hashers[$algo].TransformBlock($buffer, 0, $bytesRead, $null, 0) | Out-Null
                }
            }
        } while ($bytesRead -ne 0)

        # Finalize all hash calculations
        foreach ($algo in $Algorithms) {
            $hashers[$algo].TransformFinalBlock($buffer, 0, 0) | Out-Null
        }

        # Collect all the hash results
        $results = @{}
        foreach ($algo in $Algorithms) {
            $hashBytes = $hashers[$algo].Hash
            # Convert bytes to hex string without dashes
            $hashString = [BitConverter]::ToString($hashBytes).Replace("-", "")
            $results[$algo] = $hashString
        }

        $stream.Close()
        return $results
    }
    catch {
        Write-Log "Error processing $FilePath`: $_"
        return $null
    }
    finally {
        # Properly dispose of resources to prevent memory leaks
        if ($stream) { $stream.Dispose() }
        foreach ($algo in $Algorithms) {
            if ($hashers[$algo]) { $hashers[$algo].Dispose() }
        }
    }
}

# Function to get a timestamp in the required format (UTC)
function Get-FormattedTimestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
}

# Function to log a message to both console and the log file
# Modified Write-Log function to respect logging settings
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFilePath,
        [string]$ForegroundColor = "White",
        [string]$Status = "",
        [bool]$Force = $false,
        [bool]$IsPreviouslyAdded = $false
    )
    
    # Get current time in UTC with explicit UTC label
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
    
    # Check if we should log to terminal
    $shouldLogToTerminal = $Force -or [string]::IsNullOrEmpty($Status) -or 
                           (Should-LogStatus -Status $Status -Location "terminal" -IsPreviouslyAdded $IsPreviouslyAdded)
    
    # Write to console with color if needed
    if ($shouldLogToTerminal) {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    
    # Check if we should log to file
    $shouldLogToFile = $Force -or [string]::IsNullOrEmpty($Status) -or 
                       (Should-LogStatus -Status $Status -Location "log" -IsPreviouslyAdded $IsPreviouslyAdded)
    
    # Write to log file with timestamp if needed
    if ($shouldLogToFile -and -not [string]::IsNullOrEmpty($LogFilePath)) {
        # if this is part of a .hashtask operation we never log to file, instead we capture the data
        if ($script:operationPathType -eq "HashTask"){
            # Store in memory array instead of writing to file
            $script:logOutputCapture += "$timestamp - $Message"
        } elseif ($script:operationPathType -eq "Directory") {
            "$timestamp - $Message" | Out-File -FilePath $LogFilePath -Append -Encoding UTF8
        } else {
            Write-Host "For some weird reason the operationPathType is not properly set. Please review"
            exit 1
        }
    }
}

# Function to mark script as failed
function Mark-ScriptFailed {
    $global:scriptFailed = $true
}

# Function to ensure path ends with a backslash
function Ensure-TrailingBackslash {
    param (
        [string]$Path
    )
    
    if (-not $Path.EndsWith('\')) {
        return $Path + '\'
    }
    return $Path
}

# Function to get relative path from a base path
function Get-RelativePath {
    param (
        [string]$FullPath,
        [string]$BasePath
    )
    
    # Remove the \\?\ prefix if present for comparison
    $normalizedFullPath = $FullPath
    $normalizedBasePath = $BasePath
    
    if ($normalizedFullPath.StartsWith("\\?\")) {
        $normalizedFullPath = $normalizedFullPath.Substring(4)
    }
    
    if ($normalizedBasePath.StartsWith("\\?\")) {
        $normalizedBasePath = $normalizedBasePath.Substring(4)
    }
    
    # Ensure base path ends with a backslash
    $normalizedBasePath = Ensure-TrailingBackslash $normalizedBasePath
    
    if ($normalizedFullPath.StartsWith($normalizedBasePath, [StringComparison]::OrdinalIgnoreCase)) {
        return $normalizedFullPath.Substring($normalizedBasePath.Length)
    }
    
    # If we can't make it relative for some reason, return the full path without the prefix
    return $normalizedFullPath
}

# Create a new hash result object
function New-HashResult {
    param (
        [string]$FilePath,
        [System.IO.FileInfo]$FileInfo = $null,
        [hashtable]$Hashes = $null,
        [bool]$IsError = $false,
        [string]$ErrorMessage = "",
        [string]$BaseDirectory = "",
        [string]$Status = "",
        [string]$Comment = "",
        [string[]]$Algorithms
    )
    
    # Get relative path for CSV output
    $relativePath = if (-not [string]::IsNullOrEmpty($BaseDirectory) -and -not [string]::IsNullOrEmpty($FilePath)) {
        Get-RelativePath -FullPath $FilePath -BasePath $BaseDirectory
    } else {
        $FilePath
    }
    
    # Get file info if provided
    $fileSize = if ($FileInfo -and -not $IsError) { $FileInfo.Length } else { 0 }
    $modificationDateUTC = if ($FileInfo -and -not $IsError) { 
        $FileInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") 
    } else { 
        "" 
    }
    
    # Set hash status
    $hashStatus = if ($IsError) { 
        if ([string]::IsNullOrEmpty($Status)) { "ADDED_ERROR" } else { $Status }
    } else { 
        if ([string]::IsNullOrEmpty($Status)) { "ADDED" } else { $Status }
    }
    
    # Set comment
    $finalComment = if ($IsError -and [string]::IsNullOrEmpty($Comment)) { 
        $ErrorMessage 
    } else { 
        $Comment 
    }
    
    # Create base object
    $result = [PSCustomObject]@{
        FilePath = $relativePath
        HashStatus = $hashStatus
        FileSize = $fileSize
        ModificationDateUTC = $modificationDateUTC
        Comments = $finalComment
    }
    
    # Add hash properties
    foreach ($algo in $Algorithms) {
        $hashValue = if ($Hashes -and $Hashes.ContainsKey($algo)) { $Hashes[$algo] } else { "" }
        $result | Add-Member -MemberType NoteProperty -Name $algo -Value $hashValue
    }
    
    return $result
}

# Function to create a hash output file
function Create-HashOutputFile {
    param (
        [string]$OutputHashFile,
        [array]$Results,
        [string]$Mode,
        [int]$FileCount,
        [int]$ErrorCount,
        [int]$AddedCount,
        [int]$ModifiedCount = 0,
        [int]$DeletedCount = 0,
        [int]$IdenticalCount = 0,
        [int]$CorruptedCount = 0,
        [int]$ExcludedCount = 0,
        [int]$ReincludedCount = 0,
        [int]$SymlinkCount = 0,
        [string[]]$Algorithms,
        [string]$ScriptVersion,
        [string]$LogFilePath,
        [string]$SourcePath = "",
        [string]$SourceType = "",  # "HashTask" or "Directory" 
        [string]$ReferenceHashFile = "", # Name of reference .hashes file when applicable
        [bool]$SetReadOnly = $true  # New parameter to control read-only setting
    )
    
    try {
        Write-Log -Message "Writing hash results to disk..." -LogFilePath $LogFilePath -ForegroundColor Yellow
        
        # Function to sanitize text for CSV comments
        function Sanitize-TextForCSV {
            param ([string]$Text)
            return $Text -replace '[,;"<>]', '_'
        }
        
        # Create comment header
        $commentHeader = @()
        $commentHeader += "# PowerDirHasher metadata"
        $commentHeader += "# Generated on: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
        $commentHeader += "# PowerDirHasher version: $ScriptVersion"
        
        # Add HashTask or Folder info depending on the source
        if ($SourceType -eq "HashTask" -and -not [string]::IsNullOrEmpty($SourcePath)) {
            $sanitizedTaskName = Sanitize-TextForCSV -Text (Split-Path -Leaf $SourcePath)
            $commentHeader += "# HashTask: $sanitizedTaskName"
        } 
        elseif ($SourceType -eq "Directory" -and -not [string]::IsNullOrEmpty($SourcePath)) {
            $sanitizedFolderName = Sanitize-TextForCSV -Text ($SourcePath)
            $commentHeader += "# Folder: $sanitizedFolderName"
        }
        
        $commentHeader += "# Mode: $Mode"
        
        # Add reference hash file info for applicable modes
        if (($Mode -eq "VerifyPartialSync" -or $Mode -eq "Sync" -or $Mode -eq "VerifySync" -or $Mode -eq "Report") -and 
            -not [string]::IsNullOrEmpty($ReferenceHashFile)) {
            $sanitizedRefFileName = Sanitize-TextForCSV -Text $ReferenceHashFile
            $commentHeader += "# Hashes file used as reference: $sanitizedRefFileName"
        }
        
        $commentHeader += "# Files processed: $FileCount"
        $commentHeader += "# Files with errors: $ErrorCount"
        $commentHeader += "# Files added: $AddedCount"
        
        if ($Mode -ne "Hash") {
            $commentHeader += "# Files modified: $ModifiedCount"
            $commentHeader += "# Files deleted: $DeletedCount"
            $commentHeader += "# Files identical: $IdenticalCount"
            $commentHeader += "# Files corrupted: $CorruptedCount"
            $commentHeader += "# Files reincluded: $ReincludedCount"
        }
        
        $commentHeader += "# Files excluded: $ExcludedCount"
        $commentHeader += "# Symlinks skipped: $SymlinkCount"
        $algorithmsFormatted = $Algorithms -join " "
        $commentHeader += "# Hash algorithms used: $algorithmsFormatted"
        
        # Convert results to CSV
        $csvContent = $Results | ConvertTo-Csv -NoTypeInformation
        
        # Write the comment header followed by the CSV content
        $normalizedOutputPath = Get-NormalizedPath -Path $OutputHashFile
        $longOutputPath = Get-LongPath -Path $OutputHashFile
        $commentHeader | Out-File -LiteralPath $longOutputPath -Encoding UTF8
        $csvContent | Out-File -LiteralPath $longOutputPath -Append -Encoding UTF8
        
        # Verify the file was created
        if (Test-Path -LiteralPath $longOutputPath) {
            Write-Log -Message "Hash results saved to: $normalizedOutputPath" -LogFilePath $LogFilePath -ForegroundColor Green
            
            # Set the file to read-only if requested
            if ($SetReadOnly) {
                try {
                    $file = Get-Item -LiteralPath $longOutputPath
                    $file.IsReadOnly = $true
                    Write-Log -Message "Hash file set to read-only for protection" -LogFilePath $LogFilePath -ForegroundColor Green
                }
                catch {
                    $warningMessage = "WARNING: Could not set hash file to read-only: $($_.Exception.Message)"
                    Write-Log -Message $warningMessage -LogFilePath $LogFilePath -ForegroundColor Yellow
                    # This is not a critical error, so we'll continue
                }
            }
            
            return $true
        } else {
            throw "File was not created: $normalizedOutputPath"
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log -Message "CRITICAL ERROR: Failed to write results to disk: $errorMessage" -LogFilePath $LogFilePath -ForegroundColor Red
        Mark-ScriptFailed
        throw "Failed to write hash results: $errorMessage"
    }
}

# Handle excluded files
function Process-ExcludedFile {
    param (
        [PSObject]$FileHash,
        [string]$LogFilePath
    )
    
    # Only log once, when a file is first excluded
    if ($FileHash.HashStatus -ne "EXCLUDED") {
        Write-Log -Message "File is excluded: $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow -Status "EXCLUDED" -IsPreviouslyAdded ($FileHash.HashStatus -ne "ADDED")
        $newHashResult = $FileHash.PSObject.Copy()
        $newHashResult.HashStatus = "EXCLUDED"
        $newHashResult.Comments = ""
        # Since this is newly excluded, return the file hash with EXCLUDED status
        return @{
            HashResult = $newHashResult
            Status = "EXCLUDED"
            IsError = $false
            ErrorMessage = ""
        }
    } else {
        # File was already excluded in previous hash file, don't include it in the new one
        Write-Log -Message "File remains excluded (will be removed from hash file): $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow -Status "EXCLUDED" -IsPreviouslyAdded $true
        
        return @{
            HashResult = $null  # Return null to indicate it should be omitted
            Status = "EXCLUDED_REMOVED"
            IsError = $false
            ErrorMessage = ""
        }
    }
}

# Handle deleted files
function Process-DeletedFile {
    param (
        [PSObject]$FileHash,
        [string]$FilePath,
        [string[]]$Algorithms,
        [string]$LogFilePath
    )
    
    $longFilePath = Get-LongPath -Path $FilePath

    if (Test-Path -LiteralPath $longFilePath -PathType Leaf) {
        # The file exists again
        Write-Log -Message "File was deleted but now exists: $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow -Status "READDED" -IsPreviouslyAdded $true
        
        try {
            $result = Add-HashForFile -FilePath $FilePath -Algorithms $Algorithms -Status "READDED" -Comment "Readded files are not verified or compared to previous versions, they are added as if they were new files" -OriginalFileHash $FileHash
            
            if ($result.IsError) {
                $newHashResult = $FileHash.PSObject.Copy()
                $newHashResult.HashStatus = "READD_ERROR"
                return @{
                    HashResult = $newHashResult
                    Status = "READD_ERROR"
                    IsError = $true
                    ErrorMessage = $result.ErrorMessage
                }
            }
            
            return @{
                HashResult = $result.HashResult
                Status = "READDED"
                IsError = $false
                ErrorMessage = ""
            }
        }
        catch {
            $newHashResult = $FileHash.PSObject.Copy()
            $newHashResult.HashStatus = "READD_ERROR"
            return @{
                HashResult = $newHashResult
                Status = "READD_ERROR"
                IsError = $true
                ErrorMessage = $_.Exception.Message
            }
        }
    }
    else {
        Write-Log -Message "File remains deleted (will be removed from hash file): $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow -Status "DELETED" -IsPreviouslyAdded $true

        # File is still deleted
        return @{
            HashResult = $null
            Status = "DELETED_REMOVED"
            IsError = $false
            ErrorMessage = ""
        }
    }
}

# Mark a file as deleted
function Mark-FileAsDeleted {
    param (
        [PSObject]$FileHash,
        [string]$LogFilePath
    )
    
    Write-Log -Message "File not found (marked as deleted): $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow -Status "DELETED" -IsPreviouslyAdded $true
    
    $newHashResult = $FileHash.PSObject.Copy()
    $newHashResult.HashStatus = "DELETED"
    
    return @{
        HashResult = $newHashResult
        Status = "DELETED"
        IsError = $false
        ErrorMessage = ""
    }
}


# Process files that had errors previously
function Process-ErroredFile {
    param (
        [PSObject]$FileHash,
        [string]$FilePath,
        [string[]]$Algorithms,
        [string]$LogFilePath
    )
    
    Write-Log -Message "Retrying file that had errors: $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow -Status "ADDED_ERROR" -IsPreviouslyAdded $true
    
    $longFilePath = Get-LongPath -Path $FilePath

    try {
        $fileInfo = Get-Item -LiteralPath $longFilePath
        $hashes = Get-MultipleFileHashes -FilePath $FilePath -Algorithms $Algorithms
        
        if ($hashes) {
            # Create updated hash result
            $newHashResult = $FileHash.PSObject.Copy()
            $newHashResult.HashStatus = "ADDED_FIXED"
            $newHashResult.FileSize = $fileInfo.Length
            $newHashResult.ModificationDateUTC = $fileInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            $newHashResult.Comments = ""
            
            # Add hash values
            foreach ($algo in $Algorithms) {
                $newHashResult.$algo = $hashes[$algo]
            }
            
            return @{
                HashResult = $newHashResult
                Status = "ADDED_FIXED"
                IsError = $false
                ErrorMessage = ""
            }
        }
        else {
            # Still has errors
            $newHashResult = $FileHash.PSObject.Copy()
            $newHashResult.HashStatus = "ADDED_ERROR"
            $newHashResult.Comments = "Hash calculation failed again"
            
            return @{
                HashResult = $newHashResult
                Status = "ADDED_ERROR"
                IsError = $true
                ErrorMessage = "Failed to calculate hash again"
            }
        }
    }
    catch {
        $newHashResult = $FileHash.PSObject.Copy()
        $newHashResult.HashStatus = "ADDED_ERROR"
        $newHashResult.Comments = "Error: $($_.Exception.Message)"
        
        return @{
            HashResult = $newHashResult
            Status = "ADDED_ERROR"
            IsError = $true
            ErrorMessage = $_.Exception.Message
        }
    }
}

# Process standard file verification/sync
function Process-StandardFile {
    param (
        [PSObject]$FileHash,
        [string]$FilePath,
        [string]$Mode,
        [string[]]$Algorithms,
        [string]$LogFilePath
    )
    
    try {
        $longPath = Get-LongPath -Path $FilePath
        $fileInfo = Get-Item -LiteralPath $longPath
        $fileSize = $fileInfo.Length
        $fileModDate = $fileInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        # Check if the file has changed based on size or date
        $sizeChanged = [long]$fileSize -ne [long]$FileHash.FileSize
        $dateChanged = $fileModDate -ne $FileHash.ModificationDateUTC
        
        # For Sync mode, only calculate hashes if metadata changed
        if ($Mode -eq "Sync" -and -not ($sizeChanged -or $dateChanged)) {
            # Skip verification for unchanged files in Sync mode
            $newHashResult = $FileHash.PSObject.Copy()
            $newHashResult.HashStatus = "SKIPPED"
            
            return @{
                HashResult = $newHashResult
                Status = "SKIPPED"
                IsError = $false
                ErrorMessage = ""
            }
        }
        
        # Calculate hashes for verification
        $hashes = Get-MultipleFileHashes -FilePath $longPath -Algorithms $Algorithms
        
        if (-not $hashes) {
            # Handle hash calculation failure
            $newHashResult = $FileHash.PSObject.Copy()
            
            if ($sizeChanged -or $dateChanged) {
                $newHashResult.HashStatus = "SYNC_ERROR_SKIPPED"
                $newHashResult.Comments = "Error calculating hash for changed file"
            }
            else {
                $newHashResult.HashStatus = "VERIFY_ERROR_SKIPPED"
                $newHashResult.Comments = "Error calculating hash for verification"
            }
            
            return @{
                HashResult = $newHashResult
                Status = $newHashResult.HashStatus
                IsError = $true
                ErrorMessage = "Failed to calculate hash"
            }
        }
        
        # Determine file status based on changes
        $result = Determine-FileStatus -FileHash $FileHash -CurrentHashes $hashes -SizeChanged $sizeChanged -DateChanged $dateChanged -Algorithms $Algorithms
        
        # Create the updated hash result
        $newHashResult = $FileHash.PSObject.Copy()
        $newHashResult.HashStatus = $result.Status
        $newHashResult.FileSize = $fileSize
        $newHashResult.ModificationDateUTC = $fileModDate
        $newHashResult.Comments = $result.Comment
        
        # Update hash values
        foreach ($algo in $Algorithms) {
            $newHashResult.$algo = $hashes[$algo]
        }
        
        # When logging the file status
        Write-Log -Message "File status: $($result.Status) - $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor $(
            if ($result.Status -eq "IDENTICAL") { "Green" }
            elseif ($result.Status.StartsWith("ALERT")) { "Red" }
            elseif ($result.Status.StartsWith("MODIFIED")) { "Yellow" }
            else { "White" }
        ) -Status $result.Status -IsPreviouslyAdded $true  # Force this to true since we're looking at existing files
        
        return @{
            HashResult = $newHashResult
            Status = $result.Status
            IsError = $false
            ErrorMessage = ""
        }
    }
    catch {
        # Create a full error report
        $errorDetail = @"
ERROR: Failed to process file: $FilePath
Exception: $($_.Exception.GetType().FullName)
Message: $($_.Exception.Message)
StackTrace: $($_.ScriptStackTrace)
"@
        Write-Log -Message $errorDetail -LogFilePath $logFilePath -ForegroundColor Red -Force $true
        
        # Create an error result but preserve the original values
        $newHashResult = $FileHash.PSObject.Copy()
        $newHashResult.HashStatus = "PROCESS_ERROR"
        $newHashResult.Comments = "Error: $($_.Exception.Message)"
        
        return @{
            HashResult = $newHashResult
            Status = "PROCESS_ERROR"
            IsError = $true
            ErrorMessage = $_.Exception.Message
        }
    }
}

# Determine file status based on changes
function Determine-FileStatus {
    param (
        [PSObject]$FileHash,
        [hashtable]$CurrentHashes,
        [bool]$SizeChanged,
        [bool]$DateChanged,
        [string[]]$Algorithms
    )
    
    # Compare hashes
    $hashChanged = $false
    $identicalHashes = @()
    
    foreach ($algo in $Algorithms) {
        if ($CurrentHashes[$algo] -ne $FileHash.$algo) {
            $hashChanged = $true
        }
        else {
            $identicalHashes += $algo
        }
    }
    
    # All hashes are different (no matches)
    if ($hashChanged -and $identicalHashes.Count -eq 0) {
        if ($DateChanged -and $SizeChanged) {
            return @{
                Status = "MODIFIED_DATE_SIZE"
                Comment = ""
            }
        }
        elseif ($DateChanged) {
            return @{
                Status = "MODIFIED_ONLY_DATE"
                Comment = ""
            }
        }
        elseif ($SizeChanged) {
            return @{
                Status = "ALERT_MODIFIED_ONLY_SIZE"
                Comment = "WARNING: File size changed but modification date hasn't"
            }
        }
        else {
            return @{
                Status = "ALERT_CORRUPTED"
                Comment = "WARNING: File content changed but size and date are the same"
            }
        }
    }
    # Some hashes are the same (partial match)
    elseif ($hashChanged) {
        if ($DateChanged -and $SizeChanged) {
            return @{
                Status = "ALERT_COLLISION"
                Comment = "WARNING: Different date and size with hash collision detected ($($identicalHashes -join ', ')). Very low probability event, could indicate hash algorithm error or deliberate tampering."
            }
        }
        elseif ($DateChanged) {
            return @{
                Status = "ALERT_COLLISION"
                Comment = "WARNING: Different date but same size with partial hash collision detected ($($identicalHashes -join ', '))"
            }
        }
        elseif ($SizeChanged) {
            return @{
                Status = "ALERT_COLLISION"
                Comment = "WARNING: Same date but different size with hash collision detected ($($identicalHashes -join ', ')). This could indicate tampering or a malicious attempt to create files with matching hashes."
            }
        }
        else {
            # Same date, same size, but only some hashes match
            return @{
                Status = "ALERT_HASH_INCONSISTENCY"
                Comment = "WARNING: Some hashes changed while others remained the same, but file metadata is unchanged"
            }
        }
    }
    # All hashes are the same (complete match)
    else {
        if ($DateChanged -and $SizeChanged) {
            return @{
                Status = "ALERT_COLLISION"
                Comment = "WARNING: Different date and size but identical hashes. This is extremely unlikely and suggests possible tampering or hash algorithm failure."
            }
        }
        elseif ($DateChanged) {
            return @{
                Status = "TOUCHED"
                Comment = "File date changed but content remains identical"
            }
        }
        elseif ($SizeChanged) {
            return @{
                Status = "ALERT_COLLISION"
                Comment = "WARNING: SECURITY CONCERN - Same modification date but different size with identical hashes. This strongly suggests tampering or a malicious attempt to create hash collisions."
            }
        }
        else {
            return @{
                Status = "IDENTICAL"
                Comment = ""
            }
        }
    }
}

# Helper function to add hash for a file
function Add-HashForFile {
    param (
        [string]$FilePath,
        [string[]]$Algorithms,
        [string]$Status,
        [string]$Comment,
        [PSObject]$OriginalFileHash = $null
    )
    
    try {
        $longPath = Get-LongPath -Path $FilePath
        $fileInfo = Get-Item -LiteralPath $longPath
        
        $hashes = Get-MultipleFileHashes -FilePath $FilePath -Algorithms $Algorithms
        
        if ($hashes) {
            # Create base result or copy from original
            if ($OriginalFileHash) {
                $newHashResult = $OriginalFileHash.PSObject.Copy()
                
                # Update properties
                $newHashResult.HashStatus = $Status
                $newHashResult.FileSize = $fileInfo.Length
                $newHashResult.ModificationDateUTC = $fileInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                $newHashResult.Comments = $Comment
            } else {
                $newHashResult = New-HashResult -FilePath $FilePath -FileInfo $fileInfo -Hashes $hashes -Status $Status -Comment $Comment -Algorithms $Algorithms
            }
            
            # Add hash values (only needed if OriginalFileHash is provided, as New-HashResult already adds them)
            if ($OriginalFileHash) {
                foreach ($algo in $Algorithms) {
                    $newHashResult.$algo = $hashes[$algo]
                }
            }
            
            return @{
                HashResult = $newHashResult
                IsError = $false
                ErrorMessage = ""
            }
        }
        else {
            return @{
                HashResult = $null
                IsError = $true
                ErrorMessage = "Failed to calculate hash"
            }
        }
    }
    catch {
        return @{
            HashResult = $null
            IsError = $true
            ErrorMessage = $_.Exception.Message
        }
    }
}


function Get-TaskBasePath {
    param (
        [string]$TaskFilePath
    )
        
     # Read the task file content
     $longTaskFilePath = Get-LongPath -Path $TaskFilePath
     $fileContent = Get-Content -LiteralPath $longTaskFilePath -ErrorAction Stop
     
     # Parse the .hashtask file
     $currentSection = $null
     
     foreach ($line in $fileContent) {
         # Skip empty lines
         if ([string]::IsNullOrWhiteSpace($line)) {
             continue
         }
         
         $trimmedLine = $line.Trim()
         
         # Check if this is a section header
         if ($trimmedLine -eq "base_path:") {
             $currentSection = "base_path"
             continue
         }
         
         # Process line based on current section
         if ($currentSection -eq "base_path") {
             # Store the base path (remove quotes if present)
             if (-not [string]::IsNullOrWhiteSpace($trimmedLine)) {
                 $basePath = $trimmedLine -replace '^"(.*)"$', '$1'
             }
             
             return $basePath
         }
     }
     
     # Validate the task file
     if ([string]::IsNullOrWhiteSpace($basePath)) {
         throw "Invalid .hashtask file: Missing or empty base_path section."
     }
}


# ======================================================================
# New Menu System Functions
# ======================================================================

# Display the main menu
# Update Show-MainMenu function to include all 5 operations
function Show-MainMenu {
    param (
        [string]$WorkingPath,
        [string]$PathType
    )
    
    Clear-Host
    Write-Host "PowerDirHasher (version:"$scriptVersion")" -ForegroundColor Cyan
    Write-Host "PowerShell version:"$PSVersionTable.PSVersion.Major"."$PSVersionTable.PSVersion.Minor
    
    if ($script:longPathsEnabled) {
        Write-Host "Long path support is enabled." -ForegroundColor Green
    } else {
        Write-Host "Long path support is NOT enabled." -ForegroundColor Red
    }
    
    
    if ($PathType -eq "Directory") {
        Write-Host "Working directory: $WorkingPath" -ForegroundColor Yellow
        Write-Host "Select an option:" -ForegroundColor White
        Write-Host "1. HASH files (first time hashing of files)" -ForegroundColor White
        Write-Host "2. VERIFY files with partial sync (verify non modified files, update deleted and modified)" -ForegroundColor White
        Write-Host "3. SYNC hashes (add hashes for new files, update deleted and modified)" -ForegroundColor White
        Write-Host "4. VERIFY files AND SYNC hashes (verify non modified files, add hashes for new files, update deleted and modified)" -ForegroundColor White
        Write-Host "5. REPORT current hashing status (do not hash, only compare hashes with real files and report)" -ForegroundColor White
    }
    elseif ($PathType -eq "HashTask") {
        Write-Host "Task file: $WorkingPath" -ForegroundColor Yellow
        $basePathForTask = Get-TaskBasePath -TaskFilePath $WorkingPath
        Write-Host "Working directory: $basePathForTask" -ForegroundColor Yellow
        Write-Host "Select an option:" -ForegroundColor White
        Write-Host "1. HASH files (first time hashing of files)" -ForegroundColor White
        Write-Host "2. VERIFY files with partial sync (verify non modified files, update deleted and modified)" -ForegroundColor White
        Write-Host "3. SYNC hashes (add hashes for new files, update deleted and modified)" -ForegroundColor White
        Write-Host "4. VERIFY files AND SYNC hashes (verify non modified files, add hashes for new files, update deleted and modified)" -ForegroundColor White
        Write-Host "5. REPORT current hashing status (do not hash, only compare hashes with real files and report)" -ForegroundColor White
    }
    
    Write-Host "0. Exit" -ForegroundColor White
    
    $option = Read-Host "Enter your choice"
    
    switch ($option) {
		"1" {  # For Hash operation
			if ($PathType -eq "Directory") {
				$confirm = Read-Host "Are you sure that you want to hash the files in your working directory? (Y/N)"
				if ($confirm -eq "Y" -or $confirm -eq "y") {
					Start-FileProcessing -DirectoryPath $WorkingPath -Mode "Hash" -LogPrefix "DIR-HASH"
				}
				else {
					Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
				}
			}
			elseif ($PathType -eq "HashTask") {
				$confirm = Read-Host "Are you sure that you want to hash all directories in the hash task? (Y/N)"
				if ($confirm -eq "Y" -or $confirm -eq "y") {
					Start-TaskProcessing -TaskFilePath $WorkingPath -Mode "Hash"
				}
				else {
					Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
				}
			}
		}
        "2" {
            if ($PathType -eq "Directory") {
                $confirm = Read-Host "Are you sure that you want to verify and partially sync the files in your working directory? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    Start-FileProcessing -DirectoryPath $WorkingPath -Mode "VerifyPartialSync" -LogPrefix "DIR-VERIFY-PARTIAL-SYNC"
                }
                else {
                    Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
                }
            }
            elseif ($PathType -eq "HashTask") {
                $confirm = Read-Host "Are you sure that you want to verify and partially sync all directories in the hash task? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    Start-TaskProcessing -TaskFilePath $WorkingPath -Mode "VerifyPartialSync"
                }
                else {
                    Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
                }
            }
        }
        "3" {
            if ($PathType -eq "Directory") {
                $confirm = Read-Host "Are you sure that you want to sync hashes for the files in your working directory? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    Start-FileProcessing -DirectoryPath $WorkingPath -Mode "Sync" -LogPrefix "DIR-SYNC"
                }
                else {
                    Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
                }
            }
            elseif ($PathType -eq "HashTask") {
                $confirm = Read-Host "Are you sure that you want to sync hashes for all directories in the hash task? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    Start-TaskProcessing -TaskFilePath $WorkingPath -Mode "Sync"
                }
                else {
                    Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
                }
            }
        }
        "4" {
            if ($PathType -eq "Directory") {
                $confirm = Read-Host "Are you sure that you want to verify and sync the files in your working directory? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    Start-FileProcessing -DirectoryPath $WorkingPath -Mode "VerifySync" -LogPrefix "DIR-VERIFY-SYNC"
                }
                else {
                    Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
                }
            }
            elseif ($PathType -eq "HashTask") {
                $confirm = Read-Host "Are you sure that you want to verify and sync all directories in the hash task? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    Start-TaskProcessing -TaskFilePath $WorkingPath -Mode "VerifySync"
                }
                else {
                    Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
                }
            }
        }
        "5" {
            if ($PathType -eq "Directory") {
                $confirm = Read-Host "Are you sure that you want to report the hash status for the files in your working directory? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    Start-FileProcessing -DirectoryPath $WorkingPath -Mode "Report" -LogPrefix "DIR-REPORT"
                }
                else {
                    Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
                }
            }
            elseif ($PathType -eq "HashTask") {
                $confirm = Read-Host "Are you sure that you want to report the hash status for all directories in the hash task? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    Start-TaskProcessing -TaskFilePath $WorkingPath -Mode "Report"
                }
                else {
                    Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
                }
            }
        }
        "0" {
            Write-Host "Exiting PowerDirHasher..." -ForegroundColor Yellow
            exit
        }
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-MainMenu -WorkingPath $WorkingPath -PathType $PathType
        }
    }
}

# Validate path (directory or .hashtask file)
function Test-ValidPath {
    param (
        [string]$Path,
        [switch]$DirectoryOnly,
        [switch]$HashTaskOnly
    )
    
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    
    $longPath = Get-LongPath -Path $Path

    # If DirectoryOnly is specified, only validate as a directory
    if ($DirectoryOnly) {
        return (Test-Path -LiteralPath $longPath -PathType Container)
    }
    
    # If HashTaskOnly is specified, only validate as a .hashtask file
    if ($HashTaskOnly) {
        return (Test-Path -LiteralPath $longPath -PathType Leaf) -and ($Path.ToLower().EndsWith('.hashtask'))
    }
    
    # Otherwise, check if it's either a directory or a .hashtask file
    if (Test-Path -LiteralPath $longPath -PathType Container) {
        return $true
    }
    
    if ((Test-Path -LiteralPath $longPath -PathType Leaf) -and ($Path.ToLower().EndsWith('.hashtask'))) {
        return $true
    }
    
    return $false
}

# Determine if path is a directory or .hashtask file
function Get-PathType {
    param (
        [string]$Path
    )
    
    $longPath = Get-LongPath -Path $Path

    if (Test-Path -LiteralPath $longPath -PathType Container) {
        return "Directory"
    }
    
    if ((Test-Path -LiteralPath $longPath -PathType Leaf) -and ($Path.ToLower().EndsWith('.hashtask'))) {
        return "HashTask"
    }
    
    return "Invalid"
}

# Prompt user for path (directory or .hashtask file)
function Get-PathFromUser {
    $inputPath = ""
    $validPath = $false
    
    while (-not $validPath) {
        Write-Host "You can enter either:" -ForegroundColor Cyan
        Write-Host "1. A directory path to hash files in that directory" -ForegroundColor Cyan
        Write-Host "2. A .hashtask file containing a list of directories to process" -ForegroundColor Cyan
        $inputPath = Read-Host "Please enter the full path"
        
        # Strip quotes only if they are at the beginning and end of the input path. This is useful when you drag a folder or file to the Terminal window
        if ($inputPath.StartsWith('"') -and $inputPath.EndsWith('"') -and $inputPath.Length -gt 1) {
            $inputPath = $inputPath.Substring(1, $inputPath.Length - 2)
        }

        if (Test-ValidPath -Path $inputPath) {
            $validPath = $true
        } else {
            Write-Host "The specified path does not exist or is not a valid directory or .hashtask file. Please try again." -ForegroundColor Red
        }
    }
    
    return $inputPath
}


# Find the latest hashes file in a directory
function Find-LatestHashesFile {
    param (
        [string]$DirectoryPath
    )
    
    try {
        # Get all .hashes files in the directory
        $hashesFiles = Get-ChildItem -LiteralPath $DirectoryPath -Filter "*.hashes" -File -ErrorAction Stop
        
        if ($hashesFiles.Count -eq 0) {
            return $null
        }
        
        # Sort by filename (which contains timestamp) to get the latest one
        $latestHashesFile = $hashesFiles | Sort-Object Name -Descending | Select-Object -First 1
        
        return $latestHashesFile
    }
    catch {
        Write-Log "Error finding latest hashes file: $_"
        return $null
    }
}

# Read and parse a hashes file
function Read-HashesFile {
    param (
        [string]$FilePath
    )
    
    try {
        # Read the CSV file, skipping comment lines that start with #
        $normalizedPath = Get-NormalizedPath -Path $FilePath
        $longPath = Get-LongPath -Path $FilePath
        $content = Get-Content -LiteralPath $longPath | Where-Object { -not $_.StartsWith("#") }
        
        # Parse as CSV
        $hashesData = $content | ConvertFrom-Csv
        
        # Ensure the HashStatus property is preserved exactly as it appears in the file
        if ($hashesData.Count -gt 0) {
            # Log diagnostic information
            Write-Host "Read $($hashesData.Count) records from $normalizedPath"
            Write-Host "First record: HashStatus=$($hashesData[0].HashStatus), FilePath=$($hashesData[0].FilePath)"
        }
        
        return $hashesData
    }
    catch {
        Write-Log "Error reading hashes file: $_"
        return @()
    }
}

# Process a file in the existing hashes file
function Process-ExistingFileHash {
    param (
        [PSObject]$FileHash,
        [string]$Mode,
        [string]$DirectoryPath,
        [string[]]$Algorithms,
        [string]$LogFilePath,
        [string[]]$Exclusions = @()
    )
    
    # Get the file's full path by combining directory path and relative path
    $filePath = Join-Path -Path $DirectoryPath -ChildPath $FileHash.FilePath
    $longPath = Get-LongPath -Path $filePath
    
    # Check if the file should be excluded by the current exclusions
    if ($Exclusions.Count -gt 0 -and $FileHash.HashStatus -ne "EXCLUDED") {
        if (Test-ExclusionMatch -Path $filePath -Exclusions $Exclusions) {
            Write-Log -Message "File now excluded: $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow
            
            $newHashResult = $FileHash.PSObject.Copy()
            $newHashResult.HashStatus = "EXCLUDED"
            $newHashResult.Comments = "File matches exclusion pattern"
            
            return @{
                HashResult = $newHashResult
                Status = "EXCLUDED"
                IsError = $false
                ErrorMessage = ""
            }
        }
    }
    
    # Check if previously excluded file is no longer excluded
    if ($FileHash.HashStatus -eq "EXCLUDED" -and ($Exclusions.Count -eq 0 -or -not (Test-ExclusionMatch -Path $filePath -Exclusions $Exclusions))) {
        Write-Log -Message "File reincluded (no longer excluded): $($FileHash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow
        
        # Process as a new file
        try {
            $result = Add-HashForFile -FilePath $filePath -Algorithms $Algorithms -Status "REINCLUDED" -Comment "Reincluded files are not verified or compared to previous versions, they are added as if they were new files"
            
            if ($result.IsError) {
                $newHashResult = $FileHash.PSObject.Copy()
                $newHashResult.HashStatus = "REINCLUDE_ERROR"
            
                return @{
                    HashResult = $newHashResult
                    Status = "REINCLUDE_ERROR"
                    IsError = $true
                    ErrorMessage = $result.ErrorMessage
                }
            }
            
            return @{
                HashResult = $result.HashResult
                Status = "REINCLUDED"
                IsError = $false
                ErrorMessage = ""
            }
        }
        catch {
            $newHashResult = $FileHash.PSObject.Copy()
            $newHashResult.HashStatus = "REINCLUDE_ERROR"

            return @{
                HashResult = $newHashResult
                Status = "REINCLUDE_ERROR"
                IsError = $true
                ErrorMessage = $_.Exception.Message
            }
        }
    }
    
    # Process based on current hash status
    switch ($FileHash.HashStatus) {
        "EXCLUDED" {
            return Process-ExcludedFile -FileHash $FileHash -LogFilePath $LogFilePath
        }
        "DELETED" {
            return Process-DeletedFile -FileHash $FileHash -FilePath $filePath -Algorithms $Algorithms -LogFilePath $LogFilePath
        }
        "ADDED_ERROR" {
            return Process-ErroredFile -FileHash $FileHash -FilePath $filePath -Algorithms $Algorithms -LogFilePath $LogFilePath
        }
        default {
            # Check if the file exists in the filesystem
            if (-not (Test-Path -LiteralPath $longPath -PathType Leaf)) {
                return Mark-FileAsDeleted -FileHash $FileHash -LogFilePath $LogFilePath
            }
            
            # Standard file verification/sync
            return Process-StandardFile -FileHash $FileHash -FilePath $filePath -Mode $Mode -Algorithms $Algorithms -LogFilePath $LogFilePath
        }
    }
}


# Find new files not in the existing hashes
function Find-NewFiles {
    param (
        [string]$DirectoryPath,
        [string[]]$ExistingFilePaths,
        [string[]]$Algorithms,
        [string]$LogFilePath,
        [string[]]$Exclusions = @()
    )
    
    $normalizedDirectoryPath = Ensure-TrailingBackslash $DirectoryPath
    $longDirectoryPath = Get-LongPath -Path $DirectoryPath

    # Initialize result object with all counters
    $newResult = @{
        NewFiles = @()
        Success = $true
        SymlinkCount = 0
        ExcludedCount = 0
        ErrorCount = 0
        ProcessedCount = 0
        NewFileCount = 0
        Message = ""
    }
    
    # Find all files in the directory recursively
    try {
        Write-Log -Message "Scanning for new files in $DirectoryPath..." -LogFilePath $LogFilePath -ForegroundColor Cyan -Force $true
        
        # If exclusions exist, log them
        if ($Exclusions.Count -gt 0) {
            $quotedExclusions = $exclusions | ForEach-Object { "`"$_`"" }
            Write-Log -Message "Using exclusion patterns: $($quotedExclusions -join ', ')" -LogFilePath $LogFilePath -ForegroundColor Yellow -Force $true
        }
        
        # Use Get-ChildItem to get all files
        $allFiles = Get-ChildItem -LiteralPath $longDirectoryPath -File -Recurse -Force -ErrorAction Continue -ErrorVariable getErrors
        
        # Skip the _00-hashes directory
        $hashFolderName = $script:hashFolderName
        $hashOutputDir = Join-Path -Path $DirectoryPath -ChildPath $hashFolderName

        # Skip also the hashes files for single files
        $singleFilesHashFolderName = $script:fileHashFolderName
        $singleFilesHashOutputDir = Join-Path -Path $DirectoryPath -ChildPath $singleFilesHashFolderName
        
        # Track counts and current subfolder
        $currentSubfolder = ""
        $totalFileCount = $allFiles.Count
        $newFileCount = 0
        $symlinkCount = 0
        $excludedCount = 0
        $errorCount = 0
        $processedCount = 0

        $filesInHashesFoldersCount = 0
        
        Write-Log -Message "Found total of $totalFileCount files to check" -LogFilePath $LogFilePath -ForegroundColor Cyan -Force $true
        
        foreach ($file in $allFiles) {
            
            $normalizedFilePath = Get-NormalizedPath -Path $file.FullName

            $processedCount++

            # Track subfolder changes
            if ($script:logSettings.ShowSubfolderCurrentlyBeingProcessed) {
                $folderPath = Split-Path -Parent $file.FullName
                $relativeFolder = Get-RelativePath -FullPath $folderPath -BasePath $normalizedDirectoryPath
                
                if ($relativeFolder -ne $currentSubfolder) {
                    $currentSubfolder = $relativeFolder
                    Write-Log -Message "Processing subfolder: $relativeFolder" -LogFilePath $LogFilePath -ForegroundColor Cyan -Force $true
                }
            }
            
            # Show progress periodically
            if ($processedCount % $script:logSettings.ShowProcessedFileCountEach -eq 0) {
                Write-Log -Message "Processed $processedCount of $totalFileCount files" -LogFilePath $LogFilePath -ForegroundColor Yellow -Force $true
            }
            
            # Skip files in the hashes directory
            if ($normalizedFilePath.StartsWith($hashOutputDir, [StringComparison]::OrdinalIgnoreCase)) {
                $filesInHashesFoldersCount++
                continue
            }

            # Skip also the hashes directory for single files
            if ($normalizedFilePath.StartsWith($singleFilesHashOutputDir, [StringComparison]::OrdinalIgnoreCase)) {
                $filesInHashesFoldersCount++
                continue
            }
            
            # Skip symlinks
            if ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                $symlinkCount++
                if ($symlinkCount % 100 -eq 1) {
                    Write-Log -Message "Skipped symlink: $normalizedFilePath" -LogFilePath $LogFilePath -ForegroundColor Cyan -Force $true
                }
                continue
            }
            
			# Skip excluded files
			if ($Exclusions.Count -gt 0 -and (Test-ExclusionMatch -Path $file.FullName -Exclusions $Exclusions)) {
			    $excludedCount++
			    
			    # Log based on settings
			    if ($script:logSettings.ShowInLog["excluded"] -eq "all" -or
			        $script:logSettings.ShowInTerminal["excluded"] -eq "all") {
			        # Always log if "all" is specified in either setting
			        Write-Log -Message "Skipped excluded file: $normalizedFilePath" -LogFilePath $LogFilePath -ForegroundColor Yellow -Status "EXCLUDED" -IsPreviouslyAdded $false
			    } 
			    elseif ($excludedCount -eq 1) {
			        # Log the first occurrence regardless to indicate exclusions are happening
			        Write-Log -Message "Skipping excluded files..." -LogFilePath $LogFilePath -ForegroundColor Yellow -Force $true
			    }
			    elseif ($excludedCount % 100 -eq 0) {
			        # Log a count periodically
			        Write-Log -Message "Skipped $excludedCount excluded files so far" -LogFilePath $LogFilePath -ForegroundColor Yellow -Force $true
			    }
			    
			    continue
			}
            
            # Get the relative path
            $relativePath = Get-RelativePath -FullPath $file.FullName -BasePath $normalizedDirectoryPath
            
            # Check if this is a new file
            
            if ($ExistingFilePaths -notcontains $normalizedFilePath) {

                $newFileCount++

                try {
                    # Add hash for the file
                    $result = Add-HashForFile -FilePath $file.FullName -Algorithms $Algorithms -Status "ADDED" -Comment ""

                    if (-not $result.IsError) {
                        # Update the FilePath property since Add-HashForFile doesn't set it
                        $result.HashResult.FilePath = $relativePath
                        
                        $newResult.newFiles += @{
                            HashResult = $result.HashResult
                            Status = "ADDED"
                            IsError = $false
                        }
                        
                    }
                    else {
                        # Create error result with appropriate logging
                        $errorHashResult = [PSCustomObject]@{
                            FilePath = $relativePath
                            HashStatus = "ADDED_ERROR"
                            FileSize = $file.Length
                            ModificationDateUTC = $file.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                            Comments = "Failed to calculate hash: $($result.ErrorMessage)"
                        }
                        
                        # Add empty hash properties
                        foreach ($algo in $Algorithms) {
                            $errorHashResult | Add-Member -MemberType NoteProperty -Name $algo -Value ""
                        }
                        
                        $newResult.newFiles += @{
                            HashResult = $errorHashResult
                            Status = "ADDED_ERROR"
                            IsError = $true
                        }
                        
                        $logError = $result.ErrorMessage

                        Write-Log -Message "Error calculating hash for new file: $relativePath with error: $logError" -LogFilePath $LogFilePath -ForegroundColor Red -Status "ADDED_ERROR" -Force $true

                        $ErrorCount++
                    }

                }
                catch {
                    # Handle exceptions with appropriate logging
                    $errorHashResult = [PSCustomObject]@{
                        FilePath = $relativePath
                        HashStatus = "ADDED_ERROR"
                        FileSize = $file.Length
                        ModificationDateUTC = $file.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        Comments = "Error: $($_.Exception.Message)"
                    }
                    
                    # Add empty hash properties
                    foreach ($algo in $Algorithms) {
                        $errorHashResult | Add-Member -MemberType NoteProperty -Name $algo -Value ""
                    }
                    
                    $newResult.newFiles += @{
                        HashResult = $errorHashResult
                        Status = "ADDED_ERROR"
                        IsError = $true
                    }
                    
                    Write-Log -Message "Error processing new file $relativePath`: $($_.Exception.Message)" -LogFilePath $LogFilePath -ForegroundColor Red -Status "ADDED_ERROR" -Force $true

                    $ErrorCount++
                }
                
                # Log periodically
                if ($newFileCount % 100 -eq 0) {
                    Write-Log -Message "Found $newFileCount new files so far" -LogFilePath $LogFilePath -ForegroundColor Green -Status "ADDED" -IsPreviouslyAdded $false
                }

            }
        }
        
        # Handle any errors from Get-ChildItem
        foreach ($err in $getErrors) {
            $errorMessage = $err.Exception.Message
            Write-Log -Message "WARNING: Error accessing some files or directories: $errorMessage" -LogFilePath $LogFilePath -ForegroundColor Yellow -Force $true
            $ErrorCount++
        }
        
        Write-Log -Message "Found $newFileCount new files that were added" -LogFilePath $LogFilePath -ForegroundColor Green -Force $true
        Write-Log -Message "Skipped $filesInHashesFoldersCount files that are in PowerDirHasher hash folders" -LogFilePath $LogFilePath -ForegroundColor Green -Force $true
        Write-Log -Message "Skipped $symlinkCount symlinks" -LogFilePath $LogFilePath -ForegroundColor Cyan -Force $true
        if ($excludedCount -gt 0) {
            Write-Log -Message "Skipped $excludedCount excluded files" -LogFilePath $LogFilePath -ForegroundColor Yellow -Force $true
        }
        
        $newResult.SymlinkCount = $symlinkCount
        $newResult.ExcludedCount = $excludedCount
        $newResult.ErrorCount = $ErrorCount
        $newResult.ProcessedCount = $processedCount
        $newResult.NewFileCount = $newFileCount

        return $newResult
    }
    catch {
        Write-Log -Message "ERROR: Failed to scan for new files: $($_.Exception.Message)" -LogFilePath $LogFilePath -ForegroundColor Red -Force $true
        $ErrorCount++
        $newResult.SymlinkCount = $symlinkCount
        $newResult.ExcludedCount = $excludedCount
        $newResult.ErrorCount = $ErrorCount
        $newResult.ProcessedCount = $processedCount
        $newResult.NewFileCount = $newFileCount
        $newResult.Success = $false
        $newResult.Message = "Failed to scan for new files: $($_.Exception.Message)"
        return $newResult
    }
}

# Report mode processing
function Process-ReportMode {
    param (
        [string]$DirectoryPath,
        [System.IO.FileInfo]$LatestHashesFile,
        [string]$LogFilePath,
        [string[]]$Algorithms,
        [string]$NormalizedDirectoryPath,
        [string[]]$Exclusions = @()
    )
    
    $normalizedLatestHashFilePath = Get-NormalizedPath -Path $LatestHashesFile.FullName

    Write-Log -Message "Starting report generation for directory: $DirectoryPath" -LogFilePath $LogFilePath -ForegroundColor Cyan
    Write-Log -Message "Using hash file: $($normalizedLatestHashFilePath)" -LogFilePath $LogFilePath -ForegroundColor Cyan
    
    if ($Exclusions.Count -gt 0) {
        $quotedExclusions = $exclusions | ForEach-Object { "`"$_`"" }
        Write-Log -Message "Using exclusion patterns: $($quotedExclusions -join ', ')" -LogFilePath $LogFilePath -ForegroundColor Yellow
    }
    
    # Initialize counters
    $newFilesCount = 0
    $modifiedFilesCount = 0
    $deletedFilesCount = 0
    $excludedFilesCount = 0
    $filesProcessed = 0
    $errorCount = 0
    
    $longDirectoryPath = Get-LongPath -Path $DirectoryPath

    try {
        # Read the latest hashes file
        $existingHashes = Read-HashesFile -FilePath $LatestHashesFile.FullName
        
        # Get all existing file paths from the hashes file
        $existingFilePaths = @()

        foreach ($hash in $existingHashes) {
            $filePath = Join-Path -Path $DirectoryPath -ChildPath $hash.FilePath
            $longFilePath = Get-LongPath -Path $filePath
            $existingFilePaths += $filePath
            
            # Skip excluded files
            if ($hash.HashStatus -eq "EXCLUDED") {
                $excludedFilesCount++
                continue
            }
            
            # Check if file exists
            if (-not (Test-Path -LiteralPath $longFilePath -PathType Leaf)) {
                $deletedFilesCount++
                Write-Log -Message "Deleted file: $($hash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow
            }
            else {
                # Check if this file matches exclusion patterns
                if ($Exclusions.Count -gt 0 -and (Test-ExclusionMatch -Path $filePath -Exclusions $Exclusions)) {
                    # File is now excluded but wasn't before
                    if ($hash.HashStatus -ne "EXCLUDED") {
                        $excludedFilesCount++
                        Write-Log -Message "File now excluded: $($hash.FilePath)" -LogFilePath $LogFilePath -ForegroundColor Yellow
                    }
                    continue
                }
                
                # File exists, check if modified
                $fileInfo = Get-Item -LiteralPath $longFilePath
                $fileSize = $fileInfo.Length
                $fileModDate = $fileInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                
                if ([long]$fileSize -ne [long]$hash.FileSize -or $fileModDate -ne $hash.ModificationDateUTC) {
                    $modifiedFilesCount++
                    
                    # Log details about modification
                    $details = ""
                    if ([long]$fileSize -ne [long]$hash.FileSize) {
                        $details += "size changed from $($hash.FileSize) to $fileSize bytes, "
                    }
                    if ($fileModDate -ne $hash.ModificationDateUTC) {
                        $details += "date changed from $($hash.ModificationDateUTC) to $fileModDate"
                    }
                    
                    Write-Log -Message "Modified file: $($hash.FilePath) ($details)" -LogFilePath $LogFilePath -ForegroundColor Yellow
                }
            }
            
            $filesProcessed++
        }
        
        # Find new files
        Write-Log -Message "Scanning for new files..." -LogFilePath $LogFilePath -ForegroundColor Cyan
        $allFiles = Get-ChildItem -LiteralPath $longDirectoryPath -File -Recurse -Force -ErrorAction Continue -ErrorVariable getErrors
        
        # Skip the hashes files directory
        $hashFolderName = $script:hashFolderName
        $hashOutputDir = Join-Path -Path $DirectoryPath -ChildPath $hashFolderName

        # Skip also the hashes files for single files
        $singleFilesHashFolderName = $script:fileHashFolderName
        $singleFilesHashOutputDir = Join-Path -Path $DirectoryPath -ChildPath $singleFilesHashFolderName

        
        foreach ($file in $allFiles) {

            $normalizedFilePath = Get-NormalizedPath -Path $file.FullName

            # Skip files in the hashes directory
            if ($normalizedFilePath.StartsWith($hashOutputDir, [StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            
            # Skip also the hashes directory for single files
            if ($normalizedFilePath.StartsWith($singleFilesHashOutputDir, [StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            # Skip symlinks
            if ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                continue
            }
            
            # Skip excluded files
            if ($Exclusions.Count -gt 0 -and (Test-ExclusionMatch -Path $file.FullName -Exclusions $Exclusions)) {
                continue
            }
            
            # Check if this is a new file

            if ($existingFilePaths -notcontains $normalizedFilePath) {
                $newFilesCount++
                $relativePath = Get-RelativePath -FullPath $file.FullName -BasePath $NormalizedDirectoryPath
                Write-Log -Message "New file: $relativePath" -LogFilePath $LogFilePath -ForegroundColor Green
            }
        }
        
        # Handle any errors from Get-ChildItem
        foreach ($err in $getErrors) {
            $errorMessage = $err.Exception.Message
            Write-Log -Message "WARNING: Error accessing some files or directories: $errorMessage" -LogFilePath $LogFilePath -ForegroundColor Yellow
            $errorCount++
        }
        
        # Write summary
        Write-Log -Message "=======================================================" -LogFilePath $LogFilePath -ForegroundColor Cyan
        Write-Log -Message "REPORT SUMMARY" -LogFilePath $LogFilePath -ForegroundColor Cyan
        Write-Log -Message "=======================================================" -LogFilePath $LogFilePath -ForegroundColor Cyan
        Write-Log -Message "Directory: $DirectoryPath" -LogFilePath $LogFilePath -ForegroundColor White
        Write-Log -Message "Hash file: $($normalizedLatestHashFilePath)" -LogFilePath $LogFilePath -ForegroundColor White
        Write-Log -Message "Files in hash file: $($existingHashes.Count)" -LogFilePath $LogFilePath -ForegroundColor White
        Write-Log -Message "New files detected: $newFilesCount" -LogFilePath $LogFilePath -ForegroundColor $(if ($newFilesCount -gt 0) { "Yellow" } else { "Green" })
        Write-Log -Message "Modified files detected: $modifiedFilesCount" -LogFilePath $LogFilePath -ForegroundColor $(if ($modifiedFilesCount -gt 0) { "Yellow" } else { "Green" })
        Write-Log -Message "Deleted files detected: $deletedFilesCount" -LogFilePath $LogFilePath -ForegroundColor $(if ($deletedFilesCount -gt 0) { "Yellow" } else { "Green" })
        Write-Log -Message "Excluded files detected: $excludedFilesCount" -LogFilePath $LogFilePath -ForegroundColor $(if ($excludedFilesCount -gt 0) { "Yellow" } else { "Green" })
        Write-Log -Message "Total change count: $($newFilesCount + $modifiedFilesCount + $deletedFilesCount + $excludedFilesCount)" -LogFilePath $LogFilePath -ForegroundColor $(if (($newFilesCount + $modifiedFilesCount + $deletedFilesCount + $excludedFilesCount) -gt 0) { "Yellow" } else { "Green" })
        Write-Log -Message "=======================================================" -LogFilePath $LogFilePath -ForegroundColor Cyan
        
        return @{
            Success = $true
            FilesProcessed = $filesProcessed
            ErrorCount = $errorCount
            NewFilesCount = $newFilesCount
            ModifiedFilesCount = $modifiedFilesCount
            DeletedFilesCount = $deletedFilesCount
            ExcludedFilesCount = $excludedFilesCount
            Message = "Report completed successfully"
        }
    }
    catch {
        Write-Log -Message "ERROR: Failed to generate report: $($_.Exception.Message)" -LogFilePath $LogFilePath -ForegroundColor Red
        
        return @{
            Success = $false
            FilesProcessed = $filesProcessed
            ErrorCount = $errorCount + 1
            Message = "Failed to generate report: $($_.Exception.Message)"
        }
    }
}


# ======================================================================
# Main Hashing Functions
# ======================================================================

# Core function to process files based on operation mode
function Start-FileProcessing {
    param (
        [string]$DirectoryPath,
        [string]$Mode, # Hash, VerifyPartialSync, Sync, VerifySync, Report
        [string]$LogPrefix = "",
        [string]$CustomLogFilePath = "",
        [switch]$SuppressMenu,
        [switch]$CaptureLogOutput,
        [string[]]$Exclusions = @(),
        [string]$TaskFilePath = ""
    )
    
    # For tracking current subfolder
    $currentSubfolder = ""

    # For capturing log output in memory when called from task processor
    $script:logOutputCapture = @()
    
    # Configuration - use script variables instead of hardcoded values
    $directoryPath = $DirectoryPath
    $logFolderPath = $script:logFolderPath
    $algorithms = $script:algorithms  # Use algorithms from INI
    
    # Initialize variables
    $startTime = (Get-Date).ToUniversalTime()
    $fileCount = 0
    $errorCount = 0
    $addedCount = 0
    $modifiedCount = 0
    $touchedCount = 0
    $deletedCount = 0
    $identicalCount = 0
    $corruptedCount = 0
    $excludedCount = 0
    $reincludedCount = 0
    $symlinkCount = 0
    $filesInHashesFoldersCount = 0
    $resultMessage = ""
    $results = @()  # Array to store all results in memory
    
    try {
        # Ensure directory path ends with a backslash for relative path calculations
        $normalizedDirectoryPath = Ensure-TrailingBackslash $directoryPath
        $longDirectoryPath = Get-LongPath -Path $normalizedDirectoryPath

        # Get directory name for file naming purposes
        $directoryName = (Get-Item -LiteralPath $longDirectoryPath).Name
        $timestamp = Get-FormattedTimestamp
        
        # Create log folder if it doesn't exist
        if (-not (Test-Path -LiteralPath $logFolderPath -PathType Container)) {
            try {
                New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null
                Write-Host "Created log directory: $logFolderPath" -ForegroundColor Green
            }
            catch {
                Write-Host "CRITICAL ERROR: Failed to create log directory: $_" -ForegroundColor Red
                Mark-ScriptFailed
                throw
            }
        }
        
        # Set default log prefix if none provided
        if ([string]::IsNullOrEmpty($LogPrefix)) {
            $LogPrefix = switch ($Mode) {
                "Hash" { "DIR-HASH" }
                "VerifyPartialSync" { "DIR-VERIFY-PARTIAL-SYNC" }
                "Sync" { "DIR-SYNC" }
                "VerifySync" { "DIR-VERIFY-SYNC" }
                "Report" { "DIR-REPORT" }
                default { "DIR" }
            }
        }
        
        # Define log file path
        if ([string]::IsNullOrEmpty($CustomLogFilePath)) {
            $safeChildPath = "${timestamp}_${LogPrefix}_${directoryName}.hashlog"
            $logFilePath = Join-Path -Path $logFolderPath -ChildPath $safeChildPath
        }
        else {
            $logFilePath = $CustomLogFilePath
        }
        
        # Initialize log file
        if ($script:operationPathType -eq "HashTask") {
            "# Processing folder" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        }
        else{
            "# File Processing Utility Log" | Out-File -FilePath $logFilePath -Encoding UTF8
        }
        "# Started: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        "# Directory processed: $directoryPath" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        "# Mode: $Mode" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        
        # Log exclusions if any
        if ($Exclusions.Count -gt 0) {
            $quotedExclusions = $exclusions | ForEach-Object { "`"$_`"" }
            "# Exclusions: $($quotedExclusions -join ', ')" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            Write-Log -Message "Using exclusion patterns: $($quotedExclusions -join ', ')" -LogFilePath $logFilePath -ForegroundColor Yellow
        }
        
        "# Note: Symlinks are automatically skipped (not hashed)" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        
        # Verify the specified directory exists

        if (-not (Test-Path -LiteralPath $longDirectoryPath -PathType Container)) {
            Write-Log -Message "CRITICAL ERROR: Directory to scan does not exist: $directoryPath" -LogFilePath $logFilePath -ForegroundColor Red
            Mark-ScriptFailed
            $resultMessage = "Directory to scan does not exist"
            
            if ($SuppressMenu) {
                return @{
                    Success = $false
                    FilesProcessed = 0
                    ErrorCount = 0
                    Message = $resultMessage
                    LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                }
            }
            throw "Directory to scan does not exist: $directoryPath"
        }
    
        # Create hash output directory if it doesn't exist
        $hashFolderName = $script:hashFolderName  # Use folder name from INI
        $singleFilesFolderName = $script:fileHashFolderName # This is just used to skip hashing files inside this folder
        $hashOutputDir = Join-Path -Path $normalizedDirectoryPath -ChildPath $hashFolderName
        $singleFilesHashOutputDir = Join-Path -Path $normalizedDirectoryPath -ChildPath $singleFilesFolderName
        $longHashOutputDir = Get-LongPath -Path $hashOutputDir
        

        Write-Log -Message "Hash output directory will be: $hashOutputDir" -LogFilePath $logFilePath -ForegroundColor Cyan

        if (-not (Test-Path -LiteralPath $longHashOutputDir -PathType Container)) {
            try {
                Write-Log -Message "Creating directory: $hashOutputDir" -LogFilePath $logFilePath -ForegroundColor Cyan
                $null = New-Item -Path $longHashOutputDir -ItemType Directory -Force -ErrorAction Stop
                
                if (-not (Test-Path -LiteralPath $longHashOutputDir -PathType Container)) {
                    throw "Directory creation failed even though no error was thrown"
                }
                
                Write-Log -Message "Successfully created directory: $hashOutputDir" -LogFilePath $logFilePath -ForegroundColor Green
            }
            catch {
                Write-Log -Message "CRITICAL ERROR: Could not create hash output directory: $_" -LogFilePath $logFilePath -ForegroundColor Red
                Mark-ScriptFailed
                $resultMessage = "Failed to create hash output directory: $_"
                
                if ($SuppressMenu) {
                    return @{
                        Success = $false
                        FilesProcessed = 0
                        ErrorCount = 0
                        Message = $resultMessage
                        LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                    }
                }
                throw "Failed to create hash output directory: $_"
            }
        }
        
        # Find the latest hashes file - only for non-Hash modes
        $latestHashesFile = $null
        
        if ($Mode -ne "Hash") {
            $latestHashesFile = Find-LatestHashesFile -DirectoryPath $longHashOutputDir
            
            if ($null -eq $latestHashesFile) {
                # If no existing hashes file is found and mode is not Hash, we should handle this
                if ($Mode -eq "Report") {
                    Write-Log -Message "No existing hashes file found. Cannot generate report." -LogFilePath $logFilePath -ForegroundColor Red
                    $resultMessage = "No existing hashes file found for reporting"
                    
                    if ($SuppressMenu) {
                        return @{
                            Success = $false
                            FilesProcessed = 0
                            ErrorCount = 0
                            Message = $resultMessage
                            LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                        }
                    }
                    throw "No existing hashes file found for reporting"
                }
                else {
                    # For Sync, VerifyPartialSync, or VerifySync with no existing hashes,
                    # fall back to Hash mode
                    Write-Log -Message "No existing hashes file found. Falling back to Hash mode." -LogFilePath $logFilePath -ForegroundColor Yellow
                    $Mode = "Hash"
                }
            }
            else {
                $normalizedFilePath = Get-NormalizedPath -Path $latestHashesFile.FullName
                Write-Log -Message "Found latest hashes file: $normalizedFilePath" -LogFilePath $logFilePath -ForegroundColor Green
                
                # Check if algorithms have changed - ONLY FOR NON-REPORT MODES
                if ($Mode -ne "Report") {
                    $algosChanged = Test-AlgorithmsChanged -HashesFilePath $latestHashesFile.FullName -CurrentAlgorithms $algorithms
                    
                    if ($algosChanged) {
                        $message = "The list of algorithms for this folder has changed. The previous .hashes file will be ignored and all work as if hashing it for the first time. Do you want to proceed with this folder? (Y/N)"
                        Write-Log -Message $message -LogFilePath $logFilePath -ForegroundColor Yellow
                        
                        if (-not $SuppressMenu) {
                            $proceed = Read-Host
                            
                            if ($proceed -ne "Y" -and $proceed -ne "y") {
                                Write-Log -Message "Operation cancelled by user due to algorithm change." -LogFilePath $logFilePath -ForegroundColor Yellow
                                
                                if ($SuppressMenu) {
                                    return @{
                                        Success = $false
                                        FilesProcessed = 0
                                        ErrorCount = 0
                                        Message = "Operation cancelled - algorithm change detected"
                                        LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                                    }
                                }
                                throw "Operation cancelled - algorithm change detected"
                            }
                        }
                        
                        # Fall back to Hash mode ONLY FOR NON-REPORT MODES
                        Write-Log -Message "Proceeding as if no previous hashes exist due to algorithm change." -LogFilePath $logFilePath -ForegroundColor Yellow
                        $Mode = "Hash"
                        $latestHashesFile = $null
                    }
                }
            }
        }
        
        # Define output file path based on mode
        $outputFilePrefix = switch ($Mode) {
            "Hash" { "HASH" }
            "VerifyPartialSync" { "VERIFY-PARTIAL-SYNC" }
            "Sync" { "SYNC" }
            "VerifySync" { "VERIFY-SYNC" }
            "Report" { "REPORT" } # Report mode doesn't create a hash file, but we'll define it anyway
            default { "UNKNOWN" }
        }
        
        $safeOutputChildPath = "${timestamp}_${outputFilePrefix}_${directoryName}.hashes"
        $normalizedOutputHashFile = Join-Path -Path $hashOutputDir -ChildPath $safeOutputChildPath
        $outputHashFile = Get-LongPath -Path $normalizedOutputHashFile
        
        if ($Mode -ne "Report") {
            Write-Log -Message "Output hash file will be: $normalizedOutputHashFile" -LogFilePath $logFilePath -ForegroundColor Cyan
        }
        
        # Validate hash algorithms
        $unsupportedAlgorithms = @()
        foreach ($algo in $algorithms) {
            try {
                $instance = Get-HashAlgorithm -Algorithm $algo
                $instance.Dispose()
            }
            catch {
                $unsupportedAlgorithms += $algo
                Write-Log -Message "ERROR: Hash algorithm '$algo' is not available in this .NET environment: $_" -LogFilePath $logFilePath -ForegroundColor Red
            }
        }
        
        # Exit if any algorithms are not supported
        if ($unsupportedAlgorithms.Count -gt 0) {
            Write-Log -Message "CRITICAL ERROR: The following hash algorithms are not supported on this system: $($unsupportedAlgorithms -join ', ')" -LogFilePath $logFilePath -ForegroundColor Red
            Write-Log -Message "Operation aborted. All requested algorithms must be supported." -LogFilePath $logFilePath -ForegroundColor Red
            Mark-ScriptFailed
            $resultMessage = "Unsupported hash algorithms: $($unsupportedAlgorithms -join ', ')"
            
            if ($SuppressMenu) {
                return @{
                    Success = $false
                    FilesProcessed = 0
                    ErrorCount = 0
                    Message = $resultMessage
                    LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                }
            }
            throw "Unsupported hash algorithms: $($unsupportedAlgorithms -join ', ')"
        }
        
        # Now we branch based on the mode
        switch ($Mode) {
            
            "Hash" {
                
                # Estimate file count
                Write-Log -Message "Estimating total file count (this might take a moment)..." -LogFilePath $logFilePath -ForegroundColor Cyan
                $estimatedCount = (Get-ChildItem -LiteralPath $longDirectoryPath -File -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
                Write-Log -Message "Found approximately $estimatedCount files to process." -LogFilePath $logFilePath -ForegroundColor Cyan
                
                if ($estimatedCount -gt 100000) {
                    Write-Log -Message "WARNING: Very large directory detected ($estimatedCount files). This might take a long time." -LogFilePath $logFilePath -ForegroundColor Yellow
                    $largeConfirmation = Read-Host "Do you want to continue? (Y/N)"
                    if ($largeConfirmation -ne "Y") {
                        Write-Log -Message "Operation canceled by user." -LogFilePath $logFilePath -ForegroundColor Red
                        $resultMessage = "Operation canceled by user."
                        if ($SuppressMenu) {
                            return @{
                                Success = $false
                                FilesProcessed = 0
                                ErrorCount = 0
                                Message = $resultMessage
                                LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                            }
                        }
                        throw "Operation canceled by user."
                    }
                    Write-Log -Message "User confirmed to continue with large directory." -LogFilePath $logFilePath -ForegroundColor Green
                }
                
                # Write initial status
                Write-Log -Message "Starting file hash generation..." -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Scanning: $directoryPath" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Progress will be displayed every 100 files" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "----------------------------------------------" -LogFilePath $logFilePath -ForegroundColor Cyan
                
                # Process each file one at a time using simple direct ForEach-Object approach
                try {
                    # Initialize results as ArrayList for better performance
                    $results = [System.Collections.ArrayList]::new()
                    
                    # Use -Force to include hidden files and folders
                    Get-ChildItem -LiteralPath $longDirectoryPath -File -Recurse -Force -ErrorAction Continue -ErrorVariable getErrors | ForEach-Object {
                        $file = $_
                        
                        $normalizedFullName = Get-NormalizedPath -Path $file.FullName

                        # Track subfolder changes
                        if ($script:logSettings.ShowSubfolderCurrentlyBeingProcessed) {
                            $folderPath = Split-Path -Parent $file.FullName
                            $relativeFolder = Get-RelativePath -FullPath $folderPath -BasePath $normalizedDirectoryPath
                            
                            if ($relativeFolder -ne $currentSubfolder) {
                                $currentSubfolder = $relativeFolder
                                Write-Log -Message "Processing subfolder: $relativeFolder" -LogFilePath $logFilePath -ForegroundColor Cyan -Force $true
                            }
                        }
                        
                        # Skip symlinks (files with ReparsePoint attribute)
                        if ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                            $symlinkCount++
                            # Log only every 100 symlinks to avoid excessive logging
                            if ($symlinkCount % 100 -eq 1) {
                                Write-Log -Message "Skipped 100 symlinks and now skipping symlink: $normalizedFullName" -LogFilePath $logFilePath -ForegroundColor Cyan -Force $true
                            }
                            return  # Skip to next file
                        }
                        
                        # Skip files in the _00-hashes directory. Here both $file.FullName and $hasOutputDir should have the same format with no \\?\ prefix.
                        if ($file.FullName.StartsWith($hashOutputDir, [StringComparison]::OrdinalIgnoreCase)) {
                            $filesInHashesFoldersCount++
                            return  # Skip to next file
                        }
                        
                        # Skip files in the _00-file_hashes directory. Here both $file.FullName and $singleFilesHashOutputDir should have the same format with no \\?\ prefix.
                        if ($file.FullName.StartsWith($singleFilesHashOutputDir, [StringComparison]::OrdinalIgnoreCase)) {
                            $filesInHashesFoldersCount++
                            return  # Skip to next file
                        }


                        # Skip excluded files
                        if ($Exclusions.Count -gt 0 -and (Test-ExclusionMatch -Path $file.FullName -Exclusions $Exclusions)) {
                            $excludedCount++
                            if ($excludedCount -le 5) {  # Only log the first few exclusions to avoid flooding the log, unless the .ini asks to log all
                                Write-Log -Message "Skipped excluded file: $normalizedFullName" -LogFilePath $logFilePath -ForegroundColor Yellow
                            } elseif ($excludedCount -eq 6) {
                                if (-not ($script:logSettings.ShowInLog["excluded"] -eq "All")){
                                    Write-Log -Message "Additional excluded files will not be logged individually" -LogFilePath $logFilePath -ForegroundColor Yellow -Force $true
                                }
                            } else{
                                if ($script:logSettings.ShowInLog["excluded"] -eq "All"){
                                    Write-Log -Message "Skipped excluded file: $normalizedFullName" -LogFilePath $logFilePath -ForegroundColor Yellow -Status "EXCLUDED" -IsPreviouslyAdded $false
                                }
                            }

                                            
                            return  # Skip to next file
                        }
                        
                        $fileCount++
                        
                        # Show progress based on settings
                        if ($fileCount % $script:logSettings.ShowProcessedFileCountEach -eq 0) {
                            $elapsed = ((Get-Date).ToUniversalTime()) - $startTime
                            $rate = $fileCount / $elapsed.TotalSeconds
                            Write-Log -Message "Processed $fileCount files ($($rate.ToString('0.0')) files/sec)" -LogFilePath $logFilePath -ForegroundColor Yellow -Force $true
                        }
                        
                        try {
                            # Calculate all hashes in one file read
                            $hashes = Get-MultipleFileHashes -FilePath $file.FullName -Algorithms $algorithms
                            
                            if ($hashes) {
                                # Store result in ArrayList with relative path for CSV
                                $newResult = New-HashResult -FilePath $file.FullName -FileInfo $file -Hashes $hashes -BaseDirectory $normalizedDirectoryPath -Algorithms $algorithms
                                $null = $results.Add($newResult)
                                $addedCount++
                            }
                            else {
                                # Handle hash calculation failure
                                $errorCount++
                                $errorMessage = "Hash calculation failed"
                                $newResult = New-HashResult -FilePath $file.FullName -FileInfo $file -IsError $true -ErrorMessage $errorMessage -BaseDirectory $normalizedDirectoryPath -Algorithms $algorithms
                                $null = $results.Add($newResult)
                                
                                # Log error with full path
                                Write-Log -Message "ERROR: Hash calculation failed for file: $normalizedFullName" -LogFilePath $logFilePath -ForegroundColor Red
                            }
                        }
                        catch {
                            # Handle individual file errors
                            $errorCount++
                            $errorMessage = $_.Exception.Message
                            $newResult = New-HashResult -FilePath $file.FullName -FileInfo $file -IsError $true -ErrorMessage $errorMessage -BaseDirectory $normalizedDirectoryPath -Algorithms $algorithms
                            $null = $results.Add($newResult)
                            
                            # Log error with full path
                            Write-Log -Message "ERROR: Failed to process file $($file.FullName): $errorMessage" -LogFilePath $logFilePath -ForegroundColor Red
                        }
                    }
                    
                    # Handle any errors from Get-ChildItem
                    $getErrorCount = 0
                    foreach ($err in $getErrors) {
                        $getErrorCount++
                        $errorMessage = $err.Exception.Message
                        Write-Log -Message "WARNING: Error accessing some files or directories: $errorMessage" -LogFilePath $logFilePath -ForegroundColor Yellow -Force $true
                    }

                    if ($getErrorCount -gt 0) {
                        Write-Log -Message "IMPORTANT: $getErrorCount files or directories could not be accessed and were not processed" -LogFilePath $logFilePath -ForegroundColor Red -Force $true
                        $errorCount += $getErrorCount  # Add these errors to the total error count
                    }
                    
                    # Calculate statistics
                    $endTime = (Get-Date).ToUniversalTime()
                    $duration = $endTime - $startTime
                    $rate = if ($duration.TotalSeconds -gt 0) { $fileCount / $duration.TotalSeconds } else { 0 }
                    
                    # Output summary
                    Write-Log -Message "----------------------------------------------" -LogFilePath $logFilePath -ForegroundColor Cyan
                    Write-Log -Message "Scan complete!" -LogFilePath $logFilePath -ForegroundColor Green
                    Write-Log -Message "Total files processed: $fileCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                    Write-Log -Message "Files excluded: $excludedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                    Write-Log -Message "Skipped $filesInHashesFoldersCount files that are in PowerDirHasher hash folders" -LogFilePath $LogFilePath -ForegroundColor Cyan
                    Write-Log -Message "Symlinks skipped: $symlinkCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                    Write-Log -Message "Files with errors: $errorCount" -LogFilePath $logFilePath -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Green" })
                    Write-Log -Message "Total time: $($duration.ToString('hh\:mm\:ss'))" -LogFilePath $logFilePath -ForegroundColor Cyan
                    Write-Log -Message "Average speed: $($rate.ToString('0.0')) files/second" -LogFilePath $logFilePath -ForegroundColor Cyan
                    
                    $sourceType = if ([string]::IsNullOrEmpty($TaskFilePath)) { "Directory" } else { "HashTask" }
                    $sourcePath = if ([string]::IsNullOrEmpty($TaskFilePath)) { $directoryPath } else { $TaskFilePath }
                

                    # Write the hash results file using Create-HashOutputFile
                    $null = Create-HashOutputFile -OutputHashFile $outputHashFile -Results $results -Mode $Mode -FileCount $fileCount -ErrorCount $errorCount -AddedCount $addedCount -ExcludedCount $excludedCount -SymlinkCount $symlinkCount -Algorithms $algorithms -ScriptVersion $scriptVersion -LogFilePath $logFilePath -SourcePath $sourcePath -SourceType $sourceType -SetReadOnly $script:generalSettings.SetHashFilesReadOnly
                   
                    $resultMessage = "Hash operation completed successfully"
                    # If there were file access errors we still consider it successful but the message will be different
                    if ($getErrorCount -gt 0) {
                        $resultMessage = "Hash operation completed with access errors ($getErrorCount files/folders couldn't be accessed)"
                    }

                    # Return success
                    if ($SuppressMenu) {
                        return @{
                            Success = $true
                            FilesProcessed = $fileCount
                            ErrorCount = $errorCount
                            AccessErrorCount = $getErrorCount
                            Message = $resultMessage
                            LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                        }
                    }
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Log -Message "CRITICAL ERROR: File processing failed: $errorMessage" -LogFilePath $logFilePath -ForegroundColor Red
                    Mark-ScriptFailed
                    throw "File processing failed: $errorMessage"
                }
            }  
            "Report" {
                # Report mode doesn't create a hash file, just logs the status
                $result = Process-ReportMode -DirectoryPath $directoryPath -LatestHashesFile $latestHashesFile -LogFilePath $logFilePath -Algorithms $algorithms -NormalizedDirectoryPath $normalizedDirectoryPath -Exclusions $Exclusions
                
                if ($SuppressMenu) {
                    return @{
                        Success = $result.Success
                        FilesProcessed = $result.FilesProcessed
                        ErrorCount = $result.ErrorCount
                        Message = $result.Message
                        LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                    }
                }
                return
            }
            default {
                # For VerifyPartialSync, Sync, and VerifySync modes
                
                # Read the latest hashes file
                $existingHashes = Read-HashesFile -FilePath $latestHashesFile.FullName
                
                # Initialize counters
                $totalFilesInHash = $existingHashes.Count
                $processedFiles = 0
                
                Write-Log -Message "Starting file processing in $Mode mode..." -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Found $totalFilesInHash files in existing hashes file" -LogFilePath $logFilePath -ForegroundColor Cyan
                
                # Initialize results as ArrayList
                $results = [System.Collections.ArrayList]::new()

                # Process each file in the existing hashes
                foreach ($fileHash in $existingHashes) {
                    $processedFiles++
                    
                    # Show progress every 100 files
                    if ($processedFiles % 100 -eq 0) {
                        Write-Log -Message "Processed $processedFiles of $totalFilesInHash files" -LogFilePath $logFilePath -ForegroundColor Yellow
                    }
                    
                    $result = Process-ExistingFileHash -FileHash $fileHash -Mode $Mode -DirectoryPath $directoryPath -Algorithms $algorithms -LogFilePath $logFilePath -Exclusions $Exclusions
                    
                    # Make sure error messages are reflected in Comments field
                    if ($result.IsError -and ($null -ne $result.HashResult) -and ![string]::IsNullOrEmpty($result.ErrorMessage)) {
                        $result.HashResult.Comments = "Error: $($result.ErrorMessage)"
                    }

                    if ($null -ne $result.HashResult) {
                        # Update counters based on result
                        switch ($result.Status) {
                            "IDENTICAL" { $identicalCount++ }
                            "ADDED" { $addedCount++ }
                            "DELETED" { $deletedCount++ }
                            "EXCLUDED" { $excludedCount++ }
                            "REINCLUDED" { $reincludedCount++ }
                            "MODIFIED_DATE_SIZE" { $modifiedCount++ }
                            "MODIFIED_ONLY_DATE" { $modifiedCount++ }
                            "ALERT_MODIFIED_ONLY_SIZE" { $modifiedCount++ }
                            "TOUCHED" { $touchedCount++ }
                            "ALERT_CORRUPTED" { $corruptedCount++ }
                            "VERIFY_ERROR_SKIPPED" { $errorCount++ }
                            "SYNC_ERROR_SKIPPED" { $errorCount++ }
                            default {
                                # Other statuses
                                if ($result.IsError) {
                                    $errorCount++
                                }
                            }
                        }
                        
                        # Add to results ArrayList
                        $null = $results.Add($result.HashResult)
                        $fileCount++
                    }
                    else {
                        # Just update counters for excluded files that are being removed
                        if ($result.Status -eq "EXCLUDED_REMOVED") {
                            $excludedCount++
                        }
                        elseif ($result.Status -eq "DELETED_REMOVED") {
                            # We do not add to the numbe of deleted count because the file was already marked as deleted in a previous operation.
                        }
                    }
                }
                
                # If mode is VerifySync or Sync, we need to scan for new files
                if ($Mode -eq "VerifySync" -or $Mode -eq "Sync") {
                    Write-Log -Message "Scanning for new files..." -LogFilePath $logFilePath -ForegroundColor Cyan
                    
                    # Get all existing file paths from the hashes file
                    $existingFilePaths = $existingHashes | ForEach-Object { Join-Path -Path $directoryPath -ChildPath $_.FilePath }
                    
                    # Scan the directory for new files using the refactored Find-NewFiles
                    $newFileResults = Find-NewFiles -DirectoryPath $directoryPath -ExistingFilePaths $existingFilePaths -Algorithms $algorithms -LogFilePath $logFilePath -Exclusions $Exclusions
                    
                    # Check if the scan was successful
                    if (-not $newFileResults.Success) {
                        Write-Log -Message "CRITICAL ERROR: Failed to scan for new files. Operation aborted." -LogFilePath $logFilePath -ForegroundColor Red
                        Mark-ScriptFailed
                        throw "Failed to scan for new files: $($newFileResults.Message)"
                    }

                    # Update counters
                    $symlinkCount += $newFileResults.SymlinkCount
                    $excludedCount += $newFileResults.ExcludedCount
                    $errorCount += $newFileResults.ErrorCount

                    # Add new files to results
                    foreach ($newResult in $newFileResults.NewFiles) {
                        # Use ArrayList.Add() method instead of +=
                        $null = $results.Add($newResult.HashResult)
                        $addedCount++
                        $fileCount++
                    }
                }
                
                # Write hash results file using Create-HashOutputFile
                $null = Create-HashOutputFile -OutputHashFile $outputHashFile -Results $results -Mode $Mode -FileCount $fileCount -ErrorCount $errorCount -AddedCount $addedCount -ModifiedCount $modifiedCount -DeletedCount $deletedCount -IdenticalCount $identicalCount -CorruptedCount $corruptedCount -ExcludedCount $excludedCount -ReincludedCount $reincludedCount -SymlinkCount $symlinkCount -Algorithms $algorithms -ScriptVersion $scriptVersion -LogFilePath $logFilePath -SourcePath $sourcePath -SourceType $sourceType -ReferenceHashFile $(if ($latestHashesFile) { $latestHashesFile.Name } else { "" }) -SetReadOnly $script:generalSettings.SetHashFilesReadOnly
                
                # Summarize results
                Write-Log -Message "----------------------------------------------" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Processing complete!" -LogFilePath $logFilePath -ForegroundColor Green
                Write-Log -Message "Total files processed: $fileCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files identical: $identicalCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files added: $addedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files modified: $modifiedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files touched: $touchedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files deleted: $deletedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files excluded: $excludedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files reincluded: $reincludedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files corrupted: $corruptedCount" -LogFilePath $logFilePath -ForegroundColor $(if ($corruptedCount -gt 0) { "Red" } else { "Green" })
                Write-Log -Message "Files with errors: $errorCount" -LogFilePath $logFilePath -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Green" })
                Write-Log -Message "Symlinks skipped: $symlinkCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                
                # Return result
                if ($SuppressMenu) {
                    return @{
                        Success = $true
                        FilesProcessed = $fileCount
                        ErrorCount = $errorCount
                        Message = "Operation completed successfully"
                        LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                    }
                }
            }
        }
    }
    catch {
        # This will catch any unhandled exceptions from anywhere in the script
        $errorMessage = $_.Exception.Message
        
        if ($logFilePath -and (Test-Path -LiteralPath $logFilePath)) {
            "$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC - UNHANDLED ERROR: $errorMessage" | 
                Out-File -FilePath $logFilePath -Append -Encoding UTF8
        }
        else {
            Write-Host "CRITICAL ERROR: $errorMessage" -ForegroundColor Red
        }
        
        Mark-ScriptFailed
        
        if ($SuppressMenu) {
            # Return failure information when called from task processor
            return @{
                Success = $false
                FilesProcessed = $fileCount
                ErrorCount = $errorCount
                Message = "UNHANDLED ERROR: $errorMessage"
                LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
            }
        }
    }
    finally {
        # This block ALWAYS runs, even if there are errors
        
        # Only write the summary if we have a log file
        if ($logFilePath -and (Test-Path -LiteralPath $logFilePath)) {
            # Ensure endTime is set
            $endTime = (Get-Date).ToUniversalTime()
            $duration = $endTime - $startTime
            
            # Add a properly formatted summary to the end of the log file
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            
            if ($global:scriptFailed) {
                "# OPERATION SUMMARY - FAILED WITH ERRORS" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            } else {
                "# OPERATION SUMMARY - COMPLETED SUCCESSFULLY" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
            
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# Started:  $($startTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# Finished: $($endTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# Duration: $($duration.ToString('hh\:mm\:ss'))" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# Hash algorithms used: $($algorithms -join ', ')" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            
            if ($fileCount -gt 0) {
                "# Total files processed: $fileCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                
                if ($Mode -ne "Hash") {
                    "# Files identical: $identicalCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files added: $addedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files modified: $modifiedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files deleted: $deletedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files excluded: $excludedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files reincluded: $reincludedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files corrupted: $corruptedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                }
                
                "# Files with errors: $errorCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                "# Symlinks skipped: $symlinkCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
            
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            
            if (-not $global:scriptFailed -and $Mode -ne "Report" -and $outputHashFile -and (Test-Path -LiteralPath $outputHashFile)) {
                "# Hash results file: $normalizedOutputHashFile" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            } 
            elseif ($Mode -eq "Report") {
                "# No hash results file was created (Report mode)" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
            else {
                "# No hash results file was created due to errors" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
            
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        }
        
        # Final console output
        if ($global:scriptFailed) {
            Write-Host "`nOperation FAILED with errors." -ForegroundColor Red
            if ($logFilePath -and (Test-Path -LiteralPath $logFilePath)) {
                Write-Host "See log for details: $logFilePath" -ForegroundColor Yellow
            }
        } else {
            Write-Host "`nOperation completed successfully." -ForegroundColor Green
            if ($logFilePath -and (Test-Path -LiteralPath $logFilePath)) {
                Write-Host "Log file saved to: $logFilePath" -ForegroundColor Cyan
            }
            if ($Mode -ne "Report" -and $outputHashFile -and (Test-Path -LiteralPath $outputHashFile)) {
                Write-Host "Hash results saved to: $normalizedOutputHashFile" -ForegroundColor Cyan
            }
        }
        
        # Only show menu options if not called from task processor
        if (-not $SuppressMenu) {
            # After processing is complete, require typing "menu" or "close" to proceed
            Write-Host "`nType 'menu' and press Enter to return to the main menu" -ForegroundColor Yellow
            Write-Host "Type 'close' and press Enter to exit PowerDirHasher" -ForegroundColor Yellow
            
            $userInput = ""
            while ($userInput -ne "menu" -and $userInput -ne "close") {
                $userInput = Read-Host
                if ($userInput -ne "menu" -and $userInput -ne "close") {
                    Write-Host "Type 'menu' to return to the main menu or 'close' to exit PowerDirHasher" -ForegroundColor Yellow
                }
            }
            
            if ($userInput -eq "menu") {
                Show-MainMenu -WorkingPath $DirectoryPath -PathType "Directory"
            }
            else {
                # User typed "close", so we'll exit
                Write-Host "Exiting PowerDirHasher..." -ForegroundColor Cyan
                exit
            }
        }
    }
}


# Core function to process a single file based on operation mode
function Start-SingleFileProcessing {
    param (
        [string]$FilePath,
        [string]$Mode, # Hash, VerifyPartialSync, Sync, VerifySync, Report
        [string]$LogPrefix = "",
        [string]$CustomLogFilePath = "",
        [switch]$SuppressMenu,
        [switch]$CaptureLogOutput,
        [string]$TaskFilePath = ""  # New parameter for the task file path
    )
    
    
    # For capturing log output in memory when called from task processor
    $script:logOutputCapture = @()
    
    # Configuration
    $logFolderPath = $script:logFolderPath
    $algorithms = $script:algorithms  # Use algorithms from INI
    
    # Initialize variables
    $startTime = (Get-Date).ToUniversalTime()
    $fileCount = 0
    $errorCount = 0
    $addedCount = 0
    $modifiedCount = 0
    $touchedCount = 0
    $deletedCount = 0
    $identicalCount = 0
    $corruptedCount = 0
    $excludedCount = 0
    $reincludedCount = 0
    $symlinkCount = 0
    $resultMessage = ""
    $results = @()  # Array to store all results in memory
    
    try {
        # Get file info
        $longFilePath = Get-LongPath -Path $FilePath
        $fileInfo = Get-Item -LiteralPath $longFilePath
        $fileName = $fileInfo.Name
        $parentDirectory = $fileInfo.Directory.FullName
        $normalizedParentDirectory = Get-NormalizedPath -Path $parentDirectory
        
        # Create timestamp
        $timestamp = Get-FormattedTimestamp
        
        # Create log folder if it doesn't exist
        if (-not (Test-Path -LiteralPath $logFolderPath -PathType Container)) {
            try {
                New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null
                Write-Host "Created log directory: $logFolderPath" -ForegroundColor Green
            }
            catch {
                Write-Host "CRITICAL ERROR: Failed to create log directory: $_" -ForegroundColor Red
                Mark-ScriptFailed
                throw
            }
        }
        
        # Set default log prefix if none provided
        if ([string]::IsNullOrEmpty($LogPrefix)) {
            $LogPrefix = switch ($Mode) {
                "Hash" { "FILE-HASH" }
                "VerifyPartialSync" { "FILE-VERIFY-PARTIAL-SYNC" }
                "Sync" { "FILE-SYNC" }
                "VerifySync" { "FILE-VERIFY-SYNC" }
                "Report" { "FILE-REPORT" }
                default { "FILE" }
            }
        }
        
        # Define log file path
        if ([string]::IsNullOrEmpty($CustomLogFilePath)) {
            $safeChildPath = "${timestamp}_${LogPrefix}_${fileName}.hashlog"
            $logFilePath = Join-Path -Path $logFolderPath -ChildPath $safeChildPath
        }
        else {
            $logFilePath = $CustomLogFilePath
        }
        
        # Initialize log file
        if ($script:operationPathType -eq "HashTask") {
            "# Processing single file" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        }
        else{
            "# File Processing Utility Log" | Out-File -FilePath $logFilePath -Encoding UTF8
        }
        "# Started: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        "# File processed: $FilePath" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        "# Mode: $Mode" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        
        # Verify the specified file exists
        if (-not (Test-Path -LiteralPath $longFilePath -PathType Leaf)) {
            Write-Log -Message "CRITICAL ERROR: File to process does not exist: $FilePath" -LogFilePath $logFilePath -ForegroundColor Red
            Mark-ScriptFailed
            $resultMessage = "File to process does not exist"
            
            if ($SuppressMenu) {
                return @{
                    Success = $false
                    FilesProcessed = 0
                    ErrorCount = 0
                    Message = $resultMessage
                    LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                }
            }
            throw "File to process does not exist: $FilePath"
        }
        
        # Create hash output directory if it doesn't exist
        $hashFolderName = $script:fileHashFolderName
        $hashOutputDir = Join-Path -Path $normalizedParentDirectory -ChildPath $hashFolderName
        $longHashOutputDir = Get-LongPath -Path $hashOutputDir
        
        Write-Log -Message "Hash output directory will be: $hashOutputDir" -LogFilePath $logFilePath -ForegroundColor Cyan
        
        if (-not (Test-Path -LiteralPath $longHashOutputDir -PathType Container)) {
            try {
                Write-Log -Message "Creating directory: $hashOutputDir" -LogFilePath $logFilePath -ForegroundColor Cyan
                $null = New-Item -Path $hashOutputDir -ItemType Directory -Force -ErrorAction Stop
                
                if (-not (Test-Path -LiteralPath $longHashOutputDir -PathType Container)) {
                    throw "Directory creation failed even though no error was thrown"
                }
                
                Write-Log -Message "Successfully created directory: $hashOutputDir" -LogFilePath $logFilePath -ForegroundColor Green
            }
            catch {
                Write-Log -Message "CRITICAL ERROR: Could not create hash output directory: $_" -LogFilePath $logFilePath -ForegroundColor Red
                Mark-ScriptFailed
                $resultMessage = "Failed to create hash output directory: $_"
                
                if ($SuppressMenu) {
                    return @{
                        Success = $false
                        FilesProcessed = 0
                        ErrorCount = 0
                        Message = $resultMessage
                        LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                    }
                }
                throw "Failed to create hash output directory: $_"
            }
        }
        
        
        # Find the latest hashes file - only for non-Hash modes
        $latestHashesFile = $null
        
        if ($Mode -ne "Hash") {

            $fileNameWithExtension = [System.IO.Path]::GetFileName($FilePath)
            $hashesFiles = Get-ChildItem -LiteralPath $longHashOutputDir -Filter "*_*_$fileNameWithExtension.hashes" -File -ErrorAction SilentlyContinue
            if ($hashesFiles.Count -gt 0) {
                $latestHashesFile = $hashesFiles | Sort-Object Name -Descending | Select-Object -First 1
            } else {
                $latestHashesFile = $null
            }
            
            if ($null -eq $latestHashesFile) {
                # For single file operations, if no hash file exists, we'll create one for VerifyPartialSync, VerifySync and Sync
                if ($Mode -eq "Report") {
                    Write-Log -Message "No existing hashes file found. Cannot generate report." -LogFilePath $logFilePath -ForegroundColor Yellow
                    $resultMessage = "No existing hashes file found for reporting"
                    
                    if ($SuppressMenu) {
                        return @{
                            Success = $false
                            FilesProcessed = 0
                            ErrorCount = 0
                            Message = $resultMessage
                            LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                        }
                    }
                    throw "No existing hashes file found for reporting"
                }
                else {
                    # For single file operations, create a hash file even for VerifyPartialSync and VerifySync
                    Write-Log -Message "No existing hashes file found. Creating one for the file." -LogFilePath $logFilePath -ForegroundColor Yellow
                    $Mode = "Hash"
                }
            }
            else {
                $latestHashesFileNormalizedPath = Get-NormalizedPath -Path $latestHashesFile.FullName
                Write-Log -Message "Found latest hashes file: $latestHashesFileNormalizedPath" -LogFilePath $logFilePath -ForegroundColor Green
                
                # Check if algorithms have changed - ONLY FOR NON-REPORT MODES
                if ($Mode -ne "Report") {
                    $algosChanged = Test-AlgorithmsChanged -HashesFilePath $latestHashesFile.FullName -CurrentAlgorithms $algorithms
                    
                    if ($algosChanged) {
                        $message = "The list of algorithms for this file has changed. The previous .hashes file will be ignored and all work as if hashing it for the first time. Do you want to proceed with this file? (Y/N)"
                        Write-Log -Message $message -LogFilePath $logFilePath -ForegroundColor Yellow
                        
                        if (-not $SuppressMenu) {
                            $proceed = Read-Host
                            
                            if ($proceed -ne "Y" -and $proceed -ne "y") {
                                Write-Log -Message "Operation cancelled by user due to algorithm change." -LogFilePath $logFilePath -ForegroundColor Yellow
                                
                                if ($SuppressMenu) {
                                    return @{
                                        Success = $false
                                        FilesProcessed = 0
                                        ErrorCount = 0
                                        Message = "Operation cancelled - algorithm change detected"
                                        LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                                    }
                                }
                                throw "Operation cancelled - algorithm change detected"
                            }
                        }
                        
                        # Fall back to Hash mode ONLY FOR NON-REPORT MODES
                        Write-Log -Message "Proceeding as if no previous hashes exist due to algorithm change." -LogFilePath $logFilePath -ForegroundColor Yellow
                        $Mode = "Hash"
                        $latestHashesFile = $null
                    }
                }
            }
        }
        

        # Define output file path based on mode
        $outputFilePrefix = switch ($Mode) {
            "Hash" { "HASH" }
            "VerifyPartialSync" { "VERIFY-PARTIAL-SYNC" }
            "Sync" { "SYNC" }
            "VerifySync" { "VERIFY-SYNC" }
            "Report" { "REPORT" } # Report mode doesn't create a hash file, but we'll define it anyway
            default { "UNKNOWN" }
        }
        
        $safeOutputChildPath = "${timestamp}_${outputFilePrefix}_${fileName}.hashes"
        $normalizedOutputHashFile = Join-Path -Path $hashOutputDir -ChildPath $safeOutputChildPath
        $outputHashFile = Get-LongPath -Path $normalizedOutputHashFile
        
        if ($Mode -ne "Report") {
            Write-Log -Message "Output hash file will be: $normalizedOutputHashFile" -LogFilePath $logFilePath -ForegroundColor Cyan
        }

 		# Validate hash algorithms
        $unsupportedAlgorithms = @()
        foreach ($algo in $algorithms) {
            try {
                $instance = Get-HashAlgorithm -Algorithm $algo
                $instance.Dispose()
            }
            catch {
                $unsupportedAlgorithms += $algo
                Write-Log -Message "ERROR: Hash algorithm '$algo' is not available in this .NET environment: $_" -LogFilePath $logFilePath -ForegroundColor Red
            }
        }
        
        # Exit if any algorithms are not supported
        if ($unsupportedAlgorithms.Count -gt 0) {
            Write-Log -Message "CRITICAL ERROR: The following hash algorithms are not supported on this system: $($unsupportedAlgorithms -join ', ')" -LogFilePath $logFilePath -ForegroundColor Red
            Write-Log -Message "Operation aborted. All requested algorithms must be supported." -LogFilePath $logFilePath -ForegroundColor Red
            Mark-ScriptFailed
            $resultMessage = "Unsupported hash algorithms: $($unsupportedAlgorithms -join ', ')"
            
            if ($SuppressMenu) {
                return @{
                    Success = $false
                    FilesProcessed = 0
                    ErrorCount = 0
                    Message = $resultMessage
                    LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                }
            }
            throw "Unsupported hash algorithms: $($unsupportedAlgorithms -join ', ')"
        }
        # Now we branch based on the mode
        switch ($Mode) {
            
            "Hash" {
                # Process the file
                try {
                    Write-Log -Message "Calculating hash for file: $FilePath" -LogFilePath $logFilePath -ForegroundColor Cyan
                    
                    # Return with error if it is a symlink (files with ReparsePoint attribute)
                    if ($fileInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                        $symlinkCount++
                        Write-Log -Message "Skipped symlink: $FilePath" -LogFilePath $logFilePath -ForegroundColor Cyan
                        return @{
                            Success = $false
                            FilesProcessed = 1
                            ErrorCount = 1
                            Message = "Symlinks are not processed by PowerDirHasher, the file is a symlink"
                            LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                        }
                    }
                    else {
                        $fileCount++
                        
                        try {
                            # Calculate all hashes in one file read
                            $hashes = Get-MultipleFileHashes -FilePath $FilePath -Algorithms $algorithms
                            
                            if ($hashes) {
                                # Store result in ArrayList with relative path for CSV
                                $newResult = New-HashResult -FilePath $FilePath -FileInfo $fileInfo -Hashes $hashes -BaseDirectory $parentDirectory -Algorithms $algorithms
                                $results += $newResult
                                $addedCount++
                                
                                Write-Log -Message "Successfully calculated hash for file: $FilePath" -LogFilePath $logFilePath -ForegroundColor Green
                            }
                            else {
                                # Handle hash calculation failure
                                $errorCount++
                                $errorMessage = "Hash calculation failed"
                                $newResult = New-HashResult -FilePath $FilePath -FileInfo $fileInfo -IsError $true -ErrorMessage $errorMessage -BaseDirectory $parentDirectory -Algorithms $algorithms
                                $results += $newResult
                                
                                Write-Log -Message "ERROR: Hash calculation failed for file: $FilePath" -LogFilePath $logFilePath -ForegroundColor Red
                            }
                        }
                        catch {
                            # Handle individual file errors
                            $errorCount++
                            $errorMessage = $_.Exception.Message
                            $newResult = New-HashResult -FilePath $FilePath -FileInfo $fileInfo -IsError $true -ErrorMessage $errorMessage -BaseDirectory $parentDirectory -Algorithms $algorithms
                            $results += $newResult
                            
                            Write-Log -Message "ERROR: Failed to process file $FilePath`: $errorMessage" -LogFilePath $logFilePath -ForegroundColor Red
                        }
                    }
                    
                    # Write the hash results file
                    $null = Create-HashOutputFile -OutputHashFile $outputHashFile -Results $results -Mode $Mode -FileCount $fileCount -ErrorCount $errorCount -AddedCount $addedCount -SymlinkCount $symlinkCount -Algorithms $algorithms -ScriptVersion $scriptVersion -LogFilePath $logFilePath -SourcePath $sourcePath -SourceType $sourceType -SetReadOnly $script:generalSettings.SetHashFilesReadOnly
                    
                    # Return success
                    if ($SuppressMenu) {
                        return @{
                            Success = $true
                            FilesProcessed = $fileCount
                            ErrorCount = $errorCount
                            Message = "Hash operation completed successfully for file"
                            LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                        }
                    }
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Log -Message "CRITICAL ERROR: File processing failed: $errorMessage" -LogFilePath $logFilePath -ForegroundColor Red
                    Mark-ScriptFailed
                    throw "File processing failed: $errorMessage"
                }
            }
            
            "Report" {
                # Report mode for a single file
                # Read the latest hashes file
                $existingHashes = Read-HashesFile -FilePath $latestHashesFile.FullName
                
                # Find the file in the hashes
                $fileHash = $existingHashes | Where-Object { $_.FilePath -eq (Get-RelativePath -FullPath $FilePath -BasePath $parentDirectory) }
                
                if (-not $fileHash) {
                    Write-Log -Message "File not found in hashes file: $FilePath" -LogFilePath $logFilePath -ForegroundColor Yellow
                    
                    if ($SuppressMenu) {
                        return @{
                            Success = $false
                            FilesProcessed = 0
                            ErrorCount = 0
                            Message = "File not found in hashes file"
                            LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                        }
                    }
                    throw "File not found in hashes file"
                }
                
                # Check if file exists
                if (-not (Test-Path -LiteralPath $longFilePath -PathType Leaf)) {
                    Write-Log -Message "File has been deleted: $FilePath" -LogFilePath $logFilePath -ForegroundColor Yellow
                    
                    # Write summary
                    Write-Log -Message "=======================================================" -LogFilePath $logFilePath -ForegroundColor Cyan
                    Write-Log -Message "REPORT SUMMARY" -LogFilePath $logFilePath -ForegroundColor Cyan
                    Write-Log -Message "=======================================================" -LogFilePath $logFilePath -ForegroundColor Cyan
                    Write-Log -Message "File: $FilePath" -LogFilePath $logFilePath -ForegroundColor White
                    Write-Log -Message "Status: DELETED" -LogFilePath $logFilePath -ForegroundColor Yellow
                    Write-Log -Message "=======================================================" -LogFilePath $logFilePath -ForegroundColor Cyan
                    
                    if ($SuppressMenu) {
                        return @{
                            Success = $true
                            FilesProcessed = 1
                            ErrorCount = 0
                            Message = "File has been deleted"
                            LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                        }
                    }
                    return
                }
                
                # Check if file has changed
                $fileSize = $fileInfo.Length
                $fileModDate = $fileInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                
                # Compare file with hash
                $sizeChanged = [long]$fileSize -ne [long]$fileHash.FileSize
                $dateChanged = $fileModDate -ne $fileHash.ModificationDateUTC
                
                # Determine status
                $status = "NOT MODIFIED"
                $details = ""
                
                if ($sizeChanged -or $dateChanged) {
                    $status = "MODIFIED"
                    
                    if ($sizeChanged) {
                        $details += "size changed from $($fileHash.FileSize) to $fileSize bytes, "
                    }
                    if ($dateChanged) {
                        $details += "date changed from $($fileHash.ModificationDateUTC) to $fileModDate"
                    }
                }
                
                # Write summary
                Write-Log -Message "=======================================================" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "REPORT SUMMARY" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "=======================================================" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "File: $FilePath" -LogFilePath $logFilePath -ForegroundColor White
                Write-Log -Message "Status: $status" -LogFilePath $logFilePath -ForegroundColor $(if ($status -eq "NOT MODIFIED") { "Green" } else { "Yellow" })
                if ($details) {
                    Write-Log -Message "Details: $details" -LogFilePath $logFilePath -ForegroundColor Yellow
                }
                Write-Log -Message "=======================================================" -LogFilePath $logFilePath -ForegroundColor Cyan
                
                
                if ($SuppressMenu) {
                    return @{
                        Success = $true
                        FilesProcessed = 1
                        ErrorCount = 0
                        Message = "Report completed successfully"
                        LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                    }
                }
                return
            }
            
            default {
                # For VerifyPartialSync, Sync, and VerifySync modes
                
                # Read the latest hashes file
                $existingHashes = Read-HashesFile -FilePath $latestHashesFile.FullName
                
                # Find the file in the hashes
                $fileHash = $existingHashes | Where-Object { $_.FilePath -eq (Get-RelativePath -FullPath $FilePath -BasePath $parentDirectory) }
                
                # Initialize results as ArrayList
                $results = [System.Collections.ArrayList]::new()
                
                if ($fileHash) {
                    # Process the file hash
                    $result = Process-ExistingFileHash -FileHash $fileHash -Mode $Mode -DirectoryPath $normalizedParentDirectory -Algorithms $algorithms -LogFilePath $logFilePath
                    
                    # Make sure error messages are reflected in Comments field
                    if ($result.IsError -and ($null -ne $result.HashResult) -and ![string]::IsNullOrEmpty($result.ErrorMessage)) {
                        $result.HashResult.Comments = "Error: $($result.ErrorMessage)"
                    }

                    # Update counters based on result
                    switch ($result.Status) {
                        "IDENTICAL" { $identicalCount++ }
                        "ADDED" { $addedCount++ }
                        "DELETED" { $deletedCount++ }
                        "EXCLUDED" { $excludedCount++ }
                        "REINCLUDED" { $reincludedCount++ }
                        "MODIFIED_DATE_SIZE" { $modifiedCount++ }
                        "MODIFIED_ONLY_DATE" { $modifiedCount++ }
                        "ALERT_MODIFIED_ONLY_SIZE" { $modifiedCount++ }
                        "TOUCHED" {$touchedCount++}
                        "ALERT_CORRUPTED" { $corruptedCount++ }
                        "VERIFY_ERROR_SKIPPED" { $errorCount++ }
                        "SYNC_ERROR_SKIPPED" { $errorCount++ }
                        default {
                            # Other statuses
                            if ($result.IsError) {
                                $errorCount++
                            }
                        }
                    }
                    
                    # Add to results ArrayList
                    $null = $results.Add($result.HashResult)
                    $fileCount++
                }
                else {
                    # File not found in hashes, treat as new file
                    $hashes = Get-MultipleFileHashes -FilePath $FilePath -Algorithms $algorithms
                    
                    if ($hashes) {
                        # Create result
                        $newResult = New-HashResult -FilePath $FilePath -FileInfo $fileInfo -Hashes $hashes -BaseDirectory $parentDirectory -Algorithms $algorithms
                        $null = $results.Add($newResult)
                        $addedCount++
                        $fileCount++
                        
                        Write-Log -Message "Added new file: $FilePath" -LogFilePath $logFilePath -ForegroundColor Green
                    }
                    else {
                        # Handle hash calculation failure
                        $errorCount++
                        $errorMessage = "Hash calculation failed"
                        $newResult = New-HashResult -FilePath $FilePath -FileInfo $fileInfo -IsError $true -ErrorMessage $errorMessage -BaseDirectory $parentDirectory -Algorithms $algorithms
                        $null = $results.Add($newResult)
                        
                        Write-Log -Message "ERROR: Hash calculation failed for file: $FilePath" -LogFilePath $logFilePath -ForegroundColor Red
                    }
                }
                
                # Write hash results file
                $null = Create-HashOutputFile -OutputHashFile $outputHashFile -Results $results -Mode $Mode -FileCount $fileCount -ErrorCount $errorCount -AddedCount $addedCount -ModifiedCount $modifiedCount -DeletedCount $deletedCount -IdenticalCount $identicalCount -CorruptedCount $corruptedCount -ExcludedCount $excludedCount -ReincludedCount $reincludedCount -SymlinkCount $symlinkCount -Algorithms $algorithms -ScriptVersion $scriptVersion -LogFilePath $logFilePath -SourcePath $sourcePath -SourceType $sourceType -ReferenceHashFile $(if ($latestHashesFile) { $latestHashesFile.Name } else { "" }) -SetReadOnly $script:generalSettings.SetHashFilesReadOnly
                
                # Summarize results
                Write-Log -Message "----------------------------------------------" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Processing complete!" -LogFilePath $logFilePath -ForegroundColor Green
                Write-Log -Message "Total files processed: $fileCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files identical: $identicalCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files added: $addedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files modified: $modifiedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files touched: $touchedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files deleted: $deletedCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                Write-Log -Message "Files corrupted: $corruptedCount" -LogFilePath $logFilePath -ForegroundColor $(if ($corruptedCount -gt 0) { "Red" } else { "Green" })
                Write-Log -Message "Files with errors: $errorCount" -LogFilePath $logFilePath -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Green" })
                Write-Log -Message "Symlinks skipped: $symlinkCount" -LogFilePath $logFilePath -ForegroundColor Cyan
                
                # Return result
                if ($SuppressMenu) {
                    return @{
                        Success = $true
                        FilesProcessed = $fileCount
                        ErrorCount = $errorCount
                        Message = "Operation completed successfully for file"
                        LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
                    }
                }
            }
        }
    }
    catch {
        # This will catch any unhandled exceptions from anywhere in the script
        $errorMessage = $_.Exception.Message
        
        if ($logFilePath -and (Test-Path -LiteralPath $logFilePath)) {
            "$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC - UNHANDLED ERROR: $errorMessage" | 
                Out-File -FilePath $logFilePath -Append -Encoding UTF8
        }
        else {
            Write-Host "CRITICAL ERROR: $errorMessage" -ForegroundColor Red
        }
        
        Mark-ScriptFailed
        
        if ($SuppressMenu) {
            # Return failure information when called from task processor
            return @{
                Success = $false
                FilesProcessed = $fileCount
                ErrorCount = $errorCount
                Message = "UNHANDLED ERROR: $errorMessage"
                LogOutput = if ($CaptureLogOutput) { $script:logOutputCapture } else { $null }
            }
        }
    }
    finally {
        # This block ALWAYS runs, even if there are errors
        
        # Only write the summary if we have a log file
        if ($logFilePath -and (Test-Path -LiteralPath $logFilePath)) {
            # Ensure endTime is set
            $endTime = (Get-Date).ToUniversalTime()
            $duration = $endTime - $startTime
            
            # Add a properly formatted summary to the end of the log file
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            
            if ($global:scriptFailed) {
                "# OPERATION SUMMARY - FAILED WITH ERRORS" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            } else {
                "# OPERATION SUMMARY - COMPLETED SUCCESSFULLY" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
            
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# Started:  $($startTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# Finished: $($endTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# Duration: $($duration.ToString('hh\:mm\:ss'))" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            "# Hash algorithms used: $($algorithms -join ', ')" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            
            if ($fileCount -gt 0) {
                "# Total files processed: $fileCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                
                if ($Mode -ne "Hash") {
                    "# Files identical: $identicalCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files added: $addedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files modified: $modifiedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files deleted: $deletedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                    "# Files corrupted: $corruptedCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                }
                
                "# Files with errors: $errorCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                "# Symlinks skipped: $symlinkCount" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
            
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            
            if (-not $global:scriptFailed -and $Mode -ne "Report" -and $outputHashFile -and (Test-Path -LiteralPath $outputHashFile)) {
                "# Hash results file: $normalizedOutputHashFile" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            } 
            elseif ($Mode -eq "Report") {
                "# No hash results file was created (Report mode)" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
            else {
                "# No hash results file was created due to errors" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
            }
            
            "# ======================================================================" | Out-File -FilePath $logFilePath -Append -Encoding UTF8
        }
        
        # Final console output
        if ($global:scriptFailed) {
            Write-Host "`nOperation FAILED with errors." -ForegroundColor Red
            if ($logFilePath -and (Test-Path -LiteralPath $logFilePath)) {
                Write-Host "See log for details: $logFilePath" -ForegroundColor Yellow
            }
        } else {
            Write-Host "`nOperation completed successfully." -ForegroundColor Green
            if ($logFilePath -and (Test-Path -LiteralPath $logFilePath)) {
                Write-Host "Log file saved to: $logFilePath" -ForegroundColor Cyan
            }
            if ($Mode -ne "Report" -and $outputHashFile -and (Test-Path -LiteralPath $outputHashFile)) {
                Write-Host "Hash results saved to: $normalizedOutputHashFile" -ForegroundColor Cyan
            }
        }
        
        # Only show menu options if not called from task processor
        if (-not $SuppressMenu) {
            # After processing is complete, require typing "menu" or "close" to proceed
            Write-Host "`nType 'menu' and press Enter to return to the main menu" -ForegroundColor Yellow
            Write-Host "Type 'close' and press Enter to exit PowerDirHasher" -ForegroundColor Yellow
            
            $userInput = ""
            while ($userInput -ne "menu" -and $userInput -ne "close") {
                $userInput = Read-Host
                if ($userInput -ne "menu" -and $userInput -ne "close") {
                    Write-Host "Type 'menu' to return to the main menu or 'close' to exit PowerDirHasher" -ForegroundColor Yellow
                }
            }
            
            if ($userInput -eq "menu") {
                Show-MainMenu -WorkingPath $parentDirectory -PathType "Directory"
            }
            else {
                # User typed "close", so we'll exit
                Write-Host "Exiting PowerDirHasher..." -ForegroundColor Cyan
                exit
            }
        }
    }
}


# Process task files for all operations
function Start-TaskProcessing {
    param (
        [string]$TaskFilePath,
        [string]$Mode = "Hash" # Hash, VerifyPartialSync, Sync, VerifySync, Report
    )
    
    # Configuration
    $logFolderPath = $script:logFolderPath  # Use path from INIs
    
    # Initialize variables for the task summary
    $taskStartTime = (Get-Date).ToUniversalTime()
    $taskSummary = @()
    $totalItems = 0
    $successfulItems = 0
    $failedItems = 0
    $totalFilesProcessed = 0
    $totalErrorCount = 0
    $totalAccessErrorCount = 0
    $basePath = $null
    $items = @()
    
    # Get the task file name for logging purposes
    $taskFileName = [System.IO.Path]::GetFileNameWithoutExtension($TaskFilePath)
    $timestamp = Get-FormattedTimestamp
    
    # Define log prefix based on mode
    $logPrefix = switch ($Mode) {
        "Hash" { "TASK-HASH" }
        "VerifyPartialSync" { "TASK-VERIFY-PARTIAL-SYNC" }
        "Sync" { "TASK-SYNC" }
        "VerifySync" { "TASK-VERIFY-SYNC" }
        "Report" { "TASK-REPORT" }
        default { "TASK" }
    }
    
    # Define the consolidated log file path
    $safeChildPath = "${timestamp}_${logPrefix}_${taskFileName}.hashlog"
    $consolidatedLogFilePath = Join-Path -Path $logFolderPath -ChildPath $safeChildPath
    
    # Create log folder if it doesn't exist
    if (-not (Test-Path -LiteralPath $logFolderPath -PathType Container)) {
        try {
            New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null
            Write-Host "Created log directory: $logFolderPath" -ForegroundColor Green
        }
        catch {
            Write-Host "CRITICAL ERROR: Failed to create log directory: $_" -ForegroundColor Red
            throw  # Re-throw to exit the script
        }
    }
    
    # Initialize the consolidated log file
    "# PowerDirHasher Task Processing Log" | Out-File -FilePath $consolidatedLogFilePath -Encoding UTF8
    "# Started: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
    "# Task file processed: $TaskFilePath" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
    "# Operation mode: $Mode" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
    "# ======================================================================" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
    
    try {
        # Read the task file content
        $longTaskFilePath = Get-LongPath -Path $TaskFilePath
        $fileContent = Get-Content -LiteralPath $longTaskFilePath -ErrorAction Stop
        
        # Parse the .hashtask file
        $currentSection = $null
        $taskItems = @()
        
        foreach ($line in $fileContent) {
            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            
            $trimmedLine = $line.Trim()
            
            # Check if this is a section header
            if ($trimmedLine -eq "base_path:") {
                $currentSection = "base_path"
                continue
            }
            elseif ($trimmedLine -eq "items:") {
                $currentSection = "items"
                continue
            }
            
            # Process line based on current section
            if ($currentSection -eq "base_path") {
                # Store the base path (remove quotes if present)
                if (-not [string]::IsNullOrWhiteSpace($trimmedLine)) {
                    $basePath = $trimmedLine -replace '^"(.*)"$', '$1'
                }
                
                $script:hashTaskBasePath = $basePath
                    
                # Ensure the base path ends with a backslash for correct path construction
                if (-not $script:hashTaskBasePath.EndsWith('\')) {
                    $script:hashTaskBasePath = $script:hashTaskBasePath + '\'
                }
            }
            elseif ($currentSection -eq "items") {
                # Store the task (folder or file with optional exclusions)
                if (-not [string]::IsNullOrWhiteSpace($trimmedLine)) {
                    $taskItems += $trimmedLine
                }
            }
        }
        
        # Parse each item line to extract path and exclusions
        foreach ($itemLine in $taskItems) {
            $itemInfo = Parse-ItemLine -ItemLine $itemLine
            if ($itemInfo.Path) {
                $items += $itemInfo
            }
        }
        
        # Validate the task file
        if ([string]::IsNullOrWhiteSpace($basePath)) {
            throw "Invalid .hashtask file: Missing or empty base_path section."
        }
        
        if ($items.Count -eq 0) {
            throw "Invalid .hashtask file: No items specified in the items section."
        }
        
        $longBasePath = Get-LongPath -Path $basePath
        
        # Validate base path exists
        if (-not (Test-Path -LiteralPath $longBasePath -PathType Container)) {
            throw "Invalid base path: '$longBasePath' does not exist or is not a directory."
        }
        
        # Validate exclusion patterns
        $hasInvalidExclusions = $false
        foreach ($item in $items) {
            # Only validate exclusions for items that are folders, not for items that are individual files
            if ($item.Path.EndsWith("\") -and $item.Exclusions.Count -gt 0) {
                $invalidExclusions = Validate-ExclusionPatterns -Exclusions $item.Exclusions
                if ($invalidExclusions.Count -gt 0) {
                    foreach ($error in $invalidExclusions) {
                        $message = "ERROR in task '$($item.Path)': $error"
                        Write-Host $message -ForegroundColor Red
                        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                    }
                    $hasInvalidExclusions = $true
                }
            }
        }
        
        if ($hasInvalidExclusions) {
            throw "Invalid exclusion patterns found in .hashtask file. Please fix the issues before proceeding."
        }
        
        # Log the base path and number of items found
        $message = "Base path: $basePath"
        Write-Host $message -ForegroundColor Cyan
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $totalItems = $items.Count
        $message = "Found $totalItems items to process."
        Write-Host $message -ForegroundColor Cyan
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        # Process each item
        foreach ($item in $items) {
            # We reset the scriptFailed varilable to false each time a new item is processed (because it tracks the success of a single folder operation not the whole task)
            $global:scriptFailed = $false
            $itemPath = $item.Path
            $exclusions = $item.Exclusions
            
            # Determine if task is a folder (ends with \)
            $isFolder = $itemPath.EndsWith("\")
            
            if (-not $isFolder) {
                # This is not a folder, so it must be a file with an extension
                if (-not $itemPath.Contains(".")) {
                    $message = "ERROR: '$itemPath' is not a folder or a supported file. All folders must end in '\'. Files without extension are not supported."
                    Write-Host $message -ForegroundColor Red
                    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                    $failedItems++
                    continue
                }
                
                # Construct the full path for the file
                if ($basePath.EndsWith("\")) {
                    $fullPath = $basePath + $itemPath
                } else {
                    $fullPath = $basePath + "\" + $itemPath
                }
                
                # Log file processing
                $message = "======================================================================="
                Write-Host $message -ForegroundColor Cyan
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                
                $message = "Processing file: $itemPath"
                Write-Host $message -ForegroundColor Cyan
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                
                $message = "Full path: $fullPath"
                Write-Host $message -ForegroundColor Cyan
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                
                # Initialize file result
                $fileResult = [PSCustomObject]@{
                    Item = $itemPath
                    FullPath = $fullPath
                    Status = "Not Processed"
                    FilesProcessed = 0
                    ErrorCount = 0
                    AccessErrorCount = 0
                    Duration = [TimeSpan]::Zero
                    Message = ""
                }
                
                # Check if file exists
                $fullLongPath = Get-LongPath -Path $fullPath

                if (-not (Test-Path -LiteralPath $fullLongPath -PathType Leaf)) {
                    $fileResult.Status = "Failed"
                    $fileResult.Message = "File does not exist"
                    $failedItems++
                    
                    $message = "ERROR: File does not exist: $fullPath"
                    Write-Host $message -ForegroundColor Red
                    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                    
                    $taskSummary += $fileResult
                    continue
                }
                
                # Process the file
                try {
                    $fileStartTime = (Get-Date).ToUniversalTime()
                    
                    # Process based on mode
                    $fileLogPrefix = switch ($Mode) {
                        "Hash" { "FILE-HASH" }
                        "VerifyPartialSync" { "FILE-VERIFY-PARTIAL-SYNC" }
                        "Sync" { "FILE-SYNC" }
                        "VerifySync" { "FILE-VERIFY-SYNC" }
                        "Report" { "FILE-REPORT" }
                        default { "FILE" }
                    }
                    
                    # Call Start-SingleFileProcessing WITHOUT exclusions for individual files
                    $result = Start-SingleFileProcessing -FilePath $fullPath -Mode $Mode -LogPrefix $fileLogPrefix -CustomLogFilePath $consolidatedLogFilePath -SuppressMenu -CaptureLogOutput -TaskFilePath $TaskFilePath
                    
                    # Write captured log output to consolidated log
                    if ($result.LogOutput) {
                        $result.LogOutput | ForEach-Object {
                            $_ | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                        }
                    }
                    
                    # Update file result
                    $fileEndTime = (Get-Date).ToUniversalTime()
                    $fileDuration = $fileEndTime - $fileStartTime
                    
                    $fileResult.Status = if ($result.Success) { "Success" } else { "Failed" }
                    $fileResult.FilesProcessed = $result.FilesProcessed
                    $fileResult.ErrorCount = $result.ErrorCount
                    $fileResult.AccessErrorCount = $result.AccessErrorCount
                    $fileResult.Duration = $fileDuration
                    $fileResult.Message = $result.Message
                    
                    # Update summary counters
                    if ($result.Success) {
                        $successfulItems++
                        $totalFilesProcessed += $result.FilesProcessed
                        $totalErrorCount += $result.ErrorCount
                        $totalAccessErrorCount += $result.AccessErrorCount
                    }
                    else {
                        $failedItems++
                    }
                    
                    $message = "Completed processing file: $fullPath"
                    Write-Host $message -ForegroundColor Green
                    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                }
                catch {
                    # Handle file processing error
                    $fileEndTime = (Get-Date).ToUniversalTime()
                    $fileDuration = $fileEndTime - $fileStartTime
                    
                    $fileResult.Status = "Failed"
                    $fileResult.Duration = $fileDuration
                    $fileResult.Message = "Error: $_"
                    $failedItems++
                    
                    $message = "ERROR: Failed to process file: $fullPath. Error: $_"
                    Write-Host $message -ForegroundColor Red
                    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                    "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                }
                
                # Add to task summary
                $taskSummary += $fileResult
                continue
            }
            
            # Construct the full path
            if ($basePath.EndsWith("\")) {
                $fullPath = $basePath + $itemPath.TrimStart("\")
            } else {
                $fullPath = $basePath + "\" + $itemPath.TrimStart("\")
            }
            
            # Log task processing
            $message = "======================================================================="
            Write-Host $message -ForegroundColor Cyan
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            
            $message = "Processing: $itemPath"
            Write-Host $message -ForegroundColor Cyan
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            
            $message = "Full path: $fullPath"
            Write-Host $message -ForegroundColor Cyan
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            
            if ($exclusions.Count -gt 0) {
                $quotedExclusions = $exclusions | ForEach-Object { "`"$_`"" }
                $message = "With exclusions: $($quotedExclusions -join ', ')"
                Write-Host $message -ForegroundColor Yellow
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            }
            
            # Initialize directory result
            $directoryResult = [PSCustomObject]@{
                Item = $itemPath
                FullPath = $fullPath
                Status = "Not Processed"
                FilesProcessed = 0
                ErrorCount = 0
                AccessErrorCount = 0
                Duration = [TimeSpan]::Zero
                Message = ""
            }
            
            # Check if directory exists
            $longDirectoryPath = Get-LongPath -Path $fullPath
            if (-not (Test-Path -LiteralPath $longDirectoryPath -PathType Container)) {
                $directoryResult.Status = "Failed"
                $directoryResult.Message = "Directory does not exist"
                $failedItems++
                
                $message = "ERROR: Directory does not exist: $fullPath"
                Write-Host $message -ForegroundColor Red
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                
                $taskSummary += $directoryResult
                continue
            }
            
            # Process the directory
            try {
                $dirStartTime = (Get-Date).ToUniversalTime()
                
                # Process based on mode - now using Start-FileProcessing for all modes
                $dirLogPrefix = switch ($Mode) {
                    "Hash" { "DIR-HASH" }
                    "VerifyPartialSync" { "DIR-VERIFY-PARTIAL-SYNC" }
                    "Sync" { "DIR-SYNC" }
                    "VerifySync" { "DIR-VERIFY-SYNC" }
                    "Report" { "DIR-REPORT" }
                    default { "DIR" }
                }
                
                # Keep exclusions for directory processing
                $result = Start-FileProcessing -DirectoryPath $fullPath -Mode $Mode -LogPrefix $dirLogPrefix -CustomLogFilePath $consolidatedLogFilePath -SuppressMenu -CaptureLogOutput -Exclusions $exclusions -TaskFilePath $TaskFilePath
                
                # Write captured log output to consolidated log
                if ($result.LogOutput) {
                    $result.LogOutput | ForEach-Object {
                        $_ | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
                    }
                }
                
                # Update directory result
                $dirEndTime = (Get-Date).ToUniversalTime()
                $dirDuration = $dirEndTime - $dirStartTime
                
                $directoryResult.Status = if ($result.Success) { "Success" } else { "Failed" }
                $directoryResult.FilesProcessed = $result.FilesProcessed
                $directoryResult.ErrorCount = $result.ErrorCount
                $directoryResult.AccessErrorCount = $result.AccessErrorCount
                $directoryResult.Duration = $dirDuration
                $directoryResult.Message = $result.Message
                
                # Update summary counters
                if ($result.Success) {
                    $successfulItems++
                    $totalFilesProcessed += $result.FilesProcessed
                    $totalErrorCount += $result.ErrorCount
                    $totalAccessErrorCount += $result.AccessErrorCount
                }
                else {
                    $failedItems++
                }
                
                $message = "Completed processing directory: $fullPath"
                Write-Host $message -ForegroundColor Green
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            }
            catch {
                # Handle directory processing error
                $dirEndTime = (Get-Date).ToUniversalTime()
                $dirDuration = $dirEndTime - $dirStartTime
                
                $directoryResult.Status = "Failed"
                $directoryResult.Duration = $dirDuration
                $directoryResult.Message = "Error: $_"
                $failedItems++
                
                $message = "ERROR: Failed to process directory: $fullPath. Error: $_"
                Write-Host $message -ForegroundColor Red
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            }
            
            # Add to task summary
            $taskSummary += $directoryResult
        }
        
        # Calculate task duration
        $taskEndTime = (Get-Date).ToUniversalTime()
        $taskDuration = $taskEndTime - $taskStartTime
        
        # Write task summary
        $message = "======================================================================="
        Write-Host $message -ForegroundColor Cyan
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "TASK SUMMARY"
        Write-Host $message -ForegroundColor Cyan
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "======================================================================="
        Write-Host $message -ForegroundColor Cyan
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        # Write standard summary info
        $message = "Task File: $TaskFilePath"
        Write-Host $message -ForegroundColor White
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "Operation Mode: $Mode"
        Write-Host $message -ForegroundColor White
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "Total Items: $totalItems"
        Write-Host $message -ForegroundColor White
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "Successful Items: $successfulItems"
        Write-Host $message -ForegroundColor $(if ($successfulItems -eq $totalItems) { "Green" } else { "White" })
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "Failed Items: $failedItems"
        Write-Host $message -ForegroundColor $(if ($failedItems -gt 0) { "Red" } else { "White" })
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "Total Files Processed: $totalFilesProcessed"
        Write-Host $message -ForegroundColor White
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "Total Errors (including access errors): $totalErrorCount"
        Write-Host $message -ForegroundColor $(if ($totalErrorCount -gt 0) { "Red" } else { "Green" })
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8

        $message = "Total Access Errors: $totalAccessErrorCount"
        Write-Host $message -ForegroundColor $(if ($totalAccessErrorCount -gt 0) { "Red" } else { "Green" })
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "Total Duration: $($taskDuration.ToString('hh\:mm\:ss'))"
        Write-Host $message -ForegroundColor White
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        # Write items details
        $message = "======================================================================="
        Write-Host $message -ForegroundColor Cyan
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "ITEM DETAILS"
        Write-Host $message -ForegroundColor Cyan
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        $message = "======================================================================="
        Write-Host $message -ForegroundColor Cyan
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        # Write detailed summary for each item
        foreach ($itemResult in $taskSummary) {
            $statusColor = switch ($itemResult.Status) {
                "Success" { "Green" }
                "Failed" { "Red" }
                default { "Yellow" }
            }
            
            $message = "Item: $($itemResult.Item)"
            Write-Host $message -ForegroundColor White
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            
            $message = "Status: $($itemResult.Status)"
            Write-Host $message -ForegroundColor $statusColor
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            
            $message = "Files Processed: $($itemResult.FilesProcessed)"
            Write-Host $message -ForegroundColor White
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            
            $message = "Total Errors (including file access errors): $($itemResult.ErrorCount)"
            Write-Host $message -ForegroundColor $(if ($itemResult.ErrorCount -gt 0) { "Red" } else { "Green" })
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8

            if ($itemResult.AccessErrorCount){
                $message = "File Access Errors: $($itemResult.AccessErrorCount)"
                Write-Host $message -ForegroundColor $(if ($itemResult.AccessErrorCount -gt 0) { "Red" } else { "Green" })
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            }
            
            $message = "Duration: $($itemResult.Duration.ToString('hh\:mm\:ss'))"
            Write-Host $message -ForegroundColor White
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            
            if (-not [string]::IsNullOrEmpty($itemResult.Message)) {
                $message = "Message: $($itemResult.Message)"
                Write-Host $message -ForegroundColor White
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
                "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
            }
            
            $message = "-----------------------------------------------------------------------"
            Write-Host $message -ForegroundColor Cyan
            $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
            "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        }
        
        $message = "Task processing complete. Log saved to: $consolidatedLogFilePath"
        Write-Host $message -ForegroundColor Green
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        # After task processing is complete, require typing "menu" or "close" to proceed
        Write-Host "`nType 'menu' and press Enter to return to the main menu" -ForegroundColor Yellow
        Write-Host "Type 'close' and press Enter to exit PowerDirHasher" -ForegroundColor Yellow
        
        $userInput = ""
        while ($userInput -ne "menu" -and $userInput -ne "close") {
            $userInput = Read-Host
            if ($userInput -ne "menu" -and $userInput -ne "close") {
                Write-Host "Type 'menu' to return to the main menu or 'close' to exit PowerDirHasher" -ForegroundColor Yellow
            }
        }
        
        if ($userInput -eq "menu") {
            Show-MainMenu -WorkingPath $TaskFilePath -PathType "HashTask"
        }
        else {
            # User typed "close", so we'll exit
            Write-Host "Exiting PowerDirHasher..." -ForegroundColor Cyan
            exit
        }
    }
    catch {
        # Handle task file processing errors
        $message = "CRITICAL ERROR: Failed to process task file: $_"
        Write-Host $message -ForegroundColor Red
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        "$timestamp - $message" | Out-File -FilePath $consolidatedLogFilePath -Append -Encoding UTF8
        
        # After error, require typing "menu" or "close" to proceed
        Write-Host "`nType 'menu' and press Enter to return to the main menu" -ForegroundColor Yellow
        Write-Host "Type 'close' and press Enter to exit PowerDirHasher" -ForegroundColor Yellow
        
        $userInput = ""
        while ($userInput -ne "menu" -and $userInput -ne "close") {
            $userInput = Read-Host
            if ($userInput -ne "menu" -and $userInput -ne "close") {
                Write-Host "Type 'menu' to return to the main menu or 'close' to exit PowerDirHasher" -ForegroundColor Yellow
            }
        }
        
        if ($userInput -eq "menu") {
            Show-MainMenu -WorkingPath $TaskFilePath -PathType "HashTask"
        }
        else {
            # User typed "close", so we'll exit
            Write-Host "Exiting PowerDirHasher..." -ForegroundColor Cyan
            exit
        }
    }
    finally {
        # Clear the global variable when task processing is complete
        $script:hashTaskBasePath = $null
    }
}

# ======================================================================
# MAIN SCRIPT ENTRY POINT
# ======================================================================

# Check for EXACTLY PowerShell 5.1 (no other versions allowed)
Write-Host "PowerShell version: " $PSVersionTable.PSVersion.Major"."$PSVersionTable.PSVersion.Minor

if (-not ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1)) {
    Write-Host "ERROR: PowerDirHasher requires PowerShell 5.1 exactly. Neither older nor newer versions of PowerShell are supported." -ForegroundColor Red
    Write-Host "Current PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Write-Host "You are using PowerShell Core ($($PSVersionTable.PSVersion))." -ForegroundColor Yellow
        Write-Host "Please run this script using Windows PowerShell 5.1 instead." -ForegroundColor Yellow
        Write-Host "Look for 'Windows PowerShell' in the Start Menu (5.1 is the default version in almost any Windows 10 and Windows 11 install)." -ForegroundColor Yellow
    } else {
        Write-Host "Please use PowerShell 5.1, which is the default version included in Windows 10 and 11." -ForegroundColor Yellow
    }
    
    # Exit with error code
    exit 1
}

# Initialize settings from INI file
Initialize-Settings

# Check long paths support
$null = Check-LongPathsSupport

$script:operationPathType = "Invalid"

# Check if a path was provided (via drag and drop)
if (![string]::IsNullOrWhiteSpace($Path)) {
    Write-Host "Using provided path: $Path" -ForegroundColor Cyan
    
    # Validate the path exists
    if (Test-ValidPath -Path $Path) {
        # Determine the type of path provided
        $script:operationPathType = Get-PathType -Path $Path
        $workingPath = $Path
    } else {
        Write-Host "ERROR: The provided path '$Path' is invalid or does not exist." -ForegroundColor Red
        # Prompt the user for a valid path
        $workingPath = Get-PathFromUser
        $script:operationPathType = Get-PathType -Path $workingPath
    }
} else {
    # Prompt the user for a path
    $workingPath = Get-PathFromUser
    $script:operationPathType = Get-PathType -Path $workingPath
}

if (($script:operationPathType -eq "HashTask") -or ($script:operationPathType -eq "Directory")){
    # Start the menu system
    Show-MainMenu -WorkingPath $workingPath -PathType $script:operationPathType
} else {
    Write-Host "The path type was not set correctly" -ForegroundColor Red
    exit 1
}


