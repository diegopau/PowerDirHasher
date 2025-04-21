# Specify the file path
$filePath = "README.md"

# Store the original file attributes
$originalFile = Get-Item $filePath
$originalLastWriteTime = $originalFile.LastWriteTime
$originalCreationTime = $originalFile.CreationTime

# Read the existing content
$content = Get-Content -Path $filePath -Raw

# Modify the content (adding or removing data will change size)
$modifiedContent = $content + "`nAdditional content!!"
# Alternative: $modifiedContent = $content.Substring(0, [Math]::Max(1, $content.Length - 10))

# Write the modified content back
Set-Content -Path $filePath -Value $modifiedContent -NoNewline

# Restore the original timestamps
$file = Get-Item $filePath
$file.LastWriteTime = $originalLastWriteTime
$file.CreationTime = $originalCreationTime

Write-Host "Modification complete: Content and size changed, timestamps preserved"