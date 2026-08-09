# Image Header Scanner Module

## Overview
Added a new scanning module to wp-scan that quickly checks image file headers for malicious code. This helps detect a common attack vector where hackers inject PHP code into image files, which can be executed if the server is misconfigured or if there are vulnerabilities in image processing.

## What It Does
The image header scanner:

1. **Finds image files** - Scans all common image formats (jpg, jpeg, png, gif, webp, ico, svg, bmp)
2. **Checks headers** - Reads the first 1KB of each file to check for malicious patterns
3. **Detects threats** - Identifies:
   - PHP code tags (`<?php`, `<?=`)
   - Dangerous functions (eval, base64_decode, system, exec, shell_exec, etc.)
   - Stealth techniques (error_reporting(0), @eval, etc.)

## Usage

### Enable the module
```bash
# Scan only image headers
./wp-scan-mod.sh --image-headers /path/to/wordpress

# Include in a custom scan
./wp-scan-mod.sh --only image-headers,backdoor,uploads-php /path/to/wordpress

# Show code context when matches found
./wp-scan-mod.sh --image-headers --sc /path/to/wordpress

# Disable in a full scan
./wp-scan-mod.sh --no-image-headers /path/to/wordpress
```

### Interactive menu
```bash
./wp-scan-mod.sh --menu /path/to/wordpress
# Then select option 19 (image-headers)
```

## Example Output

### Clean scan:
```
[+] Scanning image headers for malicious code...
 -> Scanning for PHP code in image file headers (first 1KB)...
OK: No suspicious code found in image headers (scanned up to 10000 images)
```

### Threats detected:
```
[+] Scanning image headers for malicious code...
 -> Scanning for PHP code in image file headers (first 1KB)...
!!! WARNING: PHP code found in image header: /var/www/html/wp-content/uploads/2024/01/avatar.jpg
!!! WARNING: Suspicious eval/exec pattern in image header: /var/www/html/wp-content/uploads/2024/03/photo.png
!!! WARNING: Found 2 image(s) with suspicious headers
 -> Quick analysis tips:
    - Use 'head -c 2048 <file> | strings' to view header content
    - Use 'exiftool <file>' to check metadata
    - Use 'file <file>' to verify actual file type
    - Check file size - hacked images are often larger than normal
```

## How Hacked Images Work

### The Attack Vector
1. Attacker uploads/modifies an image file
2. PHP code is injected at the start of the file:
   ```
   <?php system($_GET['cmd']); ?>ÿØÿà...JPEG data...
   ```
3. If the server is misconfigured, accessing `image.jpg` can execute PHP code
4. Even if not directly executable, the code can be included or exploited through other vulnerabilities

### Why Check Headers?
- **Fast** - Only reads first 1KB, not entire file
- **Effective** - Malicious code is almost always in the header
- **Low false positives** - Legitimate images don't contain PHP code

## Detection Patterns

The scanner checks for:

1. **PHP Tags**: `<?php`, `<?=`
2. **Dangerous Functions**:
   - eval(), base64_decode(), gzinflate()
   - system(), exec(), shell_exec(), passthru()
   - assert()
3. **Stealth Techniques**:
   - @eval (error suppression)
   - error_reporting(0)
   - ini_set('display_errors', 0)

## Integration

### Files Modified
- `lib/core.sh` - Added DO_IMAGE_HEADERS flag and module triggers
- `lib/dispatcher.sh` - Added scan_image_headers() call
- `lib/menu.sh` - Added option 19 for interactive menu
- `wp-scan-mod.sh` - Sourced image_headers.sh module

### Files Added
- `modules/image_headers.sh` - Main scanner implementation

## Performance
- Scans up to 10,000 images per run
- Only reads first 1KB of each file
- Typical scan time: < 30 seconds for sites with thousands of images

## Future Enhancements
Potential improvements:
- Check for polyglot files (valid image + valid PHP)
- Entropy analysis for obfuscated code
- Integration with image magic number validation
- Deep scan option for full file content
- Checksum comparison against known-good uploads
