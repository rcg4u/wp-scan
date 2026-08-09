# Suspicious IP Tracking Feature

## Overview

The wp-scan script now automatically tracks and documents all IP addresses that make suspicious or potentially malicious requests to your site. This feature helps identify attackers and provides actionable information for blocking them.

## How It Works

When scanning access logs and ModSecurity logs, the script:

1. **Identifies suspicious requests** based on patterns like:
   - Attempts to access sensitive files (wp-config.php, .env)
   - SQL injection attempts
   - Directory traversal attempts
   - PHP shell uploads
   - Malicious user agents (sqlmap, nikto, etc.)
   - Command execution attempts

2. **Extracts IP addresses** from matching log lines

3. **Aggregates and counts** requests per IP address

4. **Displays a summary** showing:
   - Total unique suspicious IPs
   - Request count per IP (sorted by frequency)
   - Formatted table for easy reading

5. **Saves to file** for easy reference and blocking

## Output Format

At the end of the scan, you'll see:

```
==============================================
SUSPICIOUS IPs DETECTED
==============================================
The following IP addresses were found making suspicious/malicious requests:

Total unique suspicious IPs: 4

IP Address           | Request Count
---------------------|--------------
203.0.113.10         | 2
192.168.1.101        | 2
192.168.1.100        | 2
198.51.100.50        | 1

Consider blocking these IPs via firewall, .htaccess, or server configuration.
==============================================

Suspicious IPs have been saved to: /path/to/site/suspicious-ips.txt
```

## Saved File Location

The IPs are saved to: `<site-path>/suspicious-ips.txt`

This file contains one IP address per line (unique, sorted) for easy import into firewalls or other tools.

## Usage Examples

### Block IPs using iptables

```bash
while read ip; do
    sudo iptables -A INPUT -s "$ip" -j DROP
done < /path/to/site/suspicious-ips.txt
```

### Block IPs using .htaccess

```bash
echo "" >> .htaccess
echo "# Block suspicious IPs detected by wp-scan" >> .htaccess
while read ip; do
    echo "deny from $ip" >> .htaccess
done < suspicious-ips.txt
```

### Block IPs using CSF (ConfigServer Firewall)

```bash
while read ip; do
    csf -d "$ip" "Suspicious activity detected by wp-scan"
done < /path/to/site/suspicious-ips.txt
```

### Block IPs using fail2ban

Create a custom jail or add to existing WordPress protection rules.

## Modules That Collect IPs

The following scan modules contribute to the suspicious IP list:

- **access-logs**: Scans Apache/nginx access logs under /home/*/access-logs and /home/*/logs
- **modsec-logs**: Scans ModSecurity audit logs for blocked requests

## Notes

- IPs are only collected when the respective module finds suspicious activity
- The same IP may appear in multiple log entries; the count shows total suspicious requests
- IPs from excluded-ips.txt (if configured) are NOT collected
- Manual verification is recommended before blocking IPs to avoid false positives
- The feature works with both WordPress and non-WordPress sites (use --no-wordpress flag)

## Example Scan Commands

```bash
# Scan only access logs and show suspicious IPs
./wp-scan.sh --only access-logs /var/www/html/mysite

# Scan access logs and ModSecurity logs
./wp-scan.sh --only access-logs,modsec-logs /var/www/html/mysite

# Full scan (all modules, including IP tracking)
./wp-scan.sh /var/www/html/mysite

# Non-WordPress site
./wp-scan.sh --no-wordpress --only access-logs /var/www/html/site
```

## Troubleshooting

**No IPs detected**: 
- Verify access logs exist under /home/*/access-logs or /home/*/logs
- Check that logs contain suspicious activity patterns
- Ensure log format is standard (Common or Combined log format)

**Incorrect IP extraction**:
- The script expects standard log formats with IP as the first field
- ModSecurity logs should contain `[client IP]` format

**Permission issues**:
- The script must have read access to log directories
- Run with sudo if accessing system-level log directories
