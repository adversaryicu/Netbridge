# Export the generated master to the launcher's 100px RGBA asset size.
Add-Type -AssemblyName System.Drawing
$assetDir = Join-Path $PSScriptRoot '../assets'
$sourceImage = [Drawing.Image]::FromFile((Join-Path $assetDir 'netbridge-icon-master.png'))
$outputImage = [Drawing.Bitmap]::new(100, 100, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [Drawing.Graphics]::FromImage($outputImage)
try {
    $graphics.Clear([Drawing.Color]::Transparent)
    $graphics.CompositingMode = [Drawing.Drawing2D.CompositingMode]::SourceCopy
    $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.DrawImage($sourceImage, 0, 0, 100, 100)
    $outputImage.Save((Join-Path $assetDir 'netbridge-icon.png'), [Drawing.Imaging.ImageFormat]::Png)
} finally {
    $graphics.Dispose()
    $outputImage.Dispose()
    $sourceImage.Dispose()
}
