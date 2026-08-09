# Changes Summary: Suspicious IP Tracking Feature

## Files Modified

### 1. wp-scan.sh
**Changes made:**
- Added global variable `SUSPICIOUS_IPS=""` to collect IP addresses (line ~77)
- Added `collect_suspicious_ip()` helper function to extract IPs from access log lines (~line 562)
- Added `collect_modsec_ip()` helper function to extract IPs from ModSecurity log lines (~line 759)
- Modified `scan_plain_access_log()` to call `collect_suspicious_ip()` for each matched line
- Modified `scan_gz_access_log()` to call `collect_suspicious_ip()` for each matched line
- Modified `scan_plain_modsec_log()` to call `collect_modsec_ip()` for each matched line
- Modified `scan_gz_modsec_log()` to call `collect_modsec_ip()` for each matched line
- Added "SUSPICIOUS IPs DETECTED" output section before email notification (~line 1490)
  - Displays formatted table of IPs with request counts
  - Saves IPs to `<site-path>/suspicious-ips.txt`

### 2. modules/access_logs.sh
**Changes made:**
- Added `collect_ip_from_log()` helper function (~line 17)
- Modified `scan_plain_log()` to call `collect_ip_from_log()` for each matched line
- Modified `scan_gz_log()` to call `collect_ip_from_log()` for each matched line

## New Features

1. **Automatic IP Collection**: When suspicious log entries are detected, the script now automatically extracts and tracks the source IP addresses.

2. **Aggregated Summary**: At the end of the scan, displays:
   - Total count of unique suspicious IPs
   - Request count per IP (sorted by frequency)
   - Formatted table for easy reading

3. **File Output**: Saves all unique suspicious IPs to `suspicious-ips.txt` in the site root for easy use with firewalls and blocking tools.

4. **Integration**: Works seamlessly with existing modules:
   - Access logs scanning (--access-logs)
   - ModSecurity logs scanning (--modsec-logs)

## Behavior

- IPs are collected only when log scanning modules are enabled and find suspicious activity
- Multiple requests from the same IP are counted
- IPs are deduplicated and sorted in the output file
- Respects existing excluded-ips.txt filtering (if configured)
- Works with both WordPress and non-WordPress sites

## Testing

Successfully tested with simulated access logs containing:
- Multiple IPs making various suspicious requests
- Different attack patterns (config file access, SQL injection, malicious user agents)
- Proper counting and aggregation of repeat offenders

## Documentation

Created SUSPICIOUS_IPS_FEATURE.md with:
- Feature overview
- Usage examples for blocking IPs (iptables, .htaccess, CSF)
- Troubleshooting guide
- Example commands
