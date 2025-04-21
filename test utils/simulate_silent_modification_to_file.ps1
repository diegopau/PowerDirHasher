# Specify the file path
$filePath = "file!x.txt"

# Store the original file attributes
$originalFile = Get-Item $filePath
$originalLastWriteTime = $originalFile.LastWriteTime
$originalCreationTime = $originalFile.CreationTime
$originalSize = $originalFile.Length

# Read the file content into a byte array
$bytes = [System.IO.File]::ReadAllBytes($filePath)

# Modify some bytes without changing the file size
# Example: flip bits in the middle of the file
$modificationPoint = [Math]::Min(100, $bytes.Length / 2)
if ($bytes.Length -gt 0) {
    $bytes[$modificationPoint] = $bytes[$modificationPoint] -bxor 0xFF  # Flip all bits in this byte
}

# Write the modified content back
[System.IO.File]::WriteAllBytes($filePath, $bytes)

# Restore the original timestamps
$file = Get-Item $filePath
$file.LastWriteTime = $originalLastWriteTime
$file.CreationTime = $originalCreationTime

Write-Host "Silent corruption complete: Content changed, size unchanged, timestamps preserved"