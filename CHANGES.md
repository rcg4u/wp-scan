# WP-Scan Image Header Scanner - Implementation Summary

## Changes Made

### New Module Created
- **File**: `modules/image_headers.sh`
- **Purpose**: Scan image file headers for malicious PHP code
- **Detection Capabilities**:
  - PHP opening tags (`<?php`, `<?=`)
  - Dangerous functions (eval, base64_decode, system, exec, etc.)
  - Stealth techniques (@eval, error_reporting(0), etc.)

### Core Integration
Modified files to integrate the new module:

1. **lib/core.sh**:
   - Added `DO_IMAGE_HEADERS` flag (default: 1)
   - Updated `enable_only_defaults()` to include image-headers
   - Added `image-headers` to `set_module_flag()` and `clear_module_flag()`
   - Added `scan_image_headers()` stub function
   - Added `--image-headers` / `--no-image-headers` CLI flags
   - Updated module state preservation logic

2. **lib/dispatcher.sh**:
   - Added `scan_image_headers` to `run_modules()`
   - Added conditional call in `run_selected_modules()`

3. **lib/menu.sh**:
   - Added option 19 for image-headers module
   - Added toggle handler for interactive menu

4. **wp-scan-mod.sh**:
   - Sourced `modules/image_headers.sh`

## Usage Examples

```bash
# Scan only image headers
./wp-scan-mod.sh --only image-headers /var/www/html

# Include with other modules
./wp-scan-mod.sh --only image-headers,backdoor,uploads-php /var/www/html

# Show detected code context
./wp-scan-mod.sh --image-headers --sc /var/www/html

# Use in menu mode
./wp-scan-mod.sh --menu /var/www/html
# Then select: 19

# Disable in full scan
./wp-scan-mod.sh --no-image-headers /var/www/html
```

## Test Results

Created test environment with:
- Normal image files
- Images with PHP code in headers
- Images with base64-encoded payloads
- Images with stealth techniques
- Short-tag PHP code (`<?=`)

All detection patterns successfully identified malicious images.

### Example Detection Output
```
[+] Scanning image headers for malicious code...
 -> Scanning for PHP code in image file headers (first 1KB)...
!!! WARNING: PHP code found in image header: /path/to/hack.jpg
!!! WARNING: Suspicious eval/exec pattern in image header: /path/to/backdoor.png
!!! WARNING: Found 2 image(s) with suspicious headers
```

## Performance
- Scans up to 10,000 images per run
- Only reads first 1KB of each file
- Fast: < 30 seconds for large sites

## Documentation
- Created `IMAGE_HEADERS_FEATURE.md` with detailed feature documentation
- Includes usage examples, attack vectors, and technical details

## Future Enhancements
Potential additions:
- Polyglot file detection (valid image + valid PHP)
- Entropy analysis for heavily obfuscated code
- Magic number validation
- Deep scan mode for full file content
- Checksum comparison against known-good files
