# IoC Automation - IoC Scanner

A comprehensive PowerShell-based tool for bulk scanning of Indicators of Compromise (IoCs) through VirusTotal and AbuseIPDB APIs. This automation tool is designed for security analysts and threat hunters who need to process large volumes of IoCs efficiently.

## Features

### Core Functionality
- **Multi-IoC Type Support**: Automatically detects and processes IP addresses, domains, URLs, file hashes (MD5, SHA1, SHA256), and email addresses
- **Dual API Integration**: Combines VirusTotal and AbuseIPDB for comprehensive threat intelligence
- **Rate Limiting Management**: Intelligent API key rotation to handle rate limits efficiently
- **Progress Tracking**: Real-time progress bar with detailed status updates
- **Error Handling**: Robust error handling with detailed logging

### Output Formats
- **JSON Output**: Raw API responses for detailed analysis
- **CSV Output**: Flattened, analysis-ready data
- **Organized Structure**: Results automatically organized in subdirectories

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11
- **PowerShell**: Version 5.1 or higher
- **Internet Connection**: Required for API access
- **Permissions**: Ability to execute PowerShell scripts

### API Keys Required
1. **VirusTotal API Keys** (Multiple recommended)
   - Sign up at [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Free tier: 4 requests/minute per key
   - Multiple keys enable higher throughput

2. **AbuseIPDB API Key** (Optional)
   - Sign up at [AbuseIPDB](https://www.abuseipdb.com/api)
   - Provides IP reputation data
   - Free tier: 1,000 requests/day

## 🛠️ Installation & Setup

### 1. Download and Extract
```bash
# Clone or download the project files
# Ensure all files are in the same directory
```

### 2. Configure API Keys
Edit `api_keys.txt` with your API keys:

```txt
# VirusTotal API Keys (add multiple for better rate limiting)
your_vt_api_key_1
your_vt_api_key_2
your_vt_api_key_3

# AbuseIPDB API Key (optional, for IP reputation)
your_abuseipdb_api_key
```

**Important**: 
- Add VirusTotal keys first (one per line)
- Add AbuseIPDB key last
- Remove any empty lines or comments that might interfere

### 3. Prepare IoC Input
Edit `ioc_input.csv` with your IoCs:

```csv
IoCs
192.168.1.1
example.com
https://malicious-site.com/payload
d41d8cd98f00b204e9800998ecf8427e
```

## 🚀 Usage

### Quick Start
1. **Configure API keys** in `api_keys.txt`
2. **Add IoCs** to `ioc_input.csv`
3. **Run the scanner** by double-clicking `run_scanner.bat`
4. **Monitor progress** via the progress bar
5. **Review results** in the `results/` folder

### Command Line Usage
```powershell
# Direct PowerShell execution
powershell -ExecutionPolicy Bypass -File query_virustotal.ps1

# With logging
powershell -ExecutionPolicy Bypass -File query_virustotal.ps1 > debug_log.txt 2>&1
```

## 📊 Supported IoC Types

| Type | Format | Example | Status |
|------|--------|---------|--------|
| **IP Address** | IPv4 format | `192.168.1.1` | ✅ Supported |
| **Domain** | Standard domain | `example.com` | ✅ Supported |
| **URL** | HTTP/HTTPS URLs | `https://example.com/path` | ✅ Supported |
| **File Hash** | MD5/SHA1/SHA256 | `d41d8cd98f00b204e9800998ecf8427e` | ✅ Supported |
| **Email** | Email format | `test@example.com` | ⚠️ Skipped |

## 📁 Output Structure

```
results/
├── csvs/
│   ├── virustotal_results.csv
│   └── abuseipdb_results.csv
└── json/
    ├── virustotal_results.json
    └── abuseipdb_results.json
```

### Output Files Description

#### VirusTotal Results
- **virustotal_results.json**: Raw API responses with full metadata
- **virustotal_results.csv**: Flattened data including:
  - IoC and type information
  - Detection ratios and counts
  - Analysis dates and timestamps
  - Community votes and comments
  - File metadata (for file hashes)

#### AbuseIPDB Results (IP addresses only)
- **abuseipdb_results.json**: Raw IP reputation data
- **abuseipdb_results.csv**: Flattened reputation data including:
  - Abuse confidence percentage
  - Country and ISP information
  - Usage type classification
  - Last reported date

## Configuration Options

### Rate Limiting
- **Requests per key**: 4 requests before rotation
- **Delay between requests**: 2 seconds
- **Automatic key rotation**: Enabled

### Error Handling
- **Invalid IoCs**: Logged and skipped
- **API failures**: Retry with next key
- **Network issues**: Detailed error logging

## Troubleshooting

### Common Issues

#### "PowerShell is not installed"
- **Solution**: Install PowerShell 5.1+ from Microsoft
- **Alternative**: Use Windows PowerShell (built-in)

#### "Missing api_keys.txt"
- **Solution**: Create `api_keys.txt` with valid API keys
- **Format**: One key per line, AbuseIPDB key last

#### "No valid IoCs found"
- **Solution**: Check `ioc_input.csv` format
- **Required**: Header row with "IoCs" column

#### "API rate limit exceeded"
- **Solution**: Add more VirusTotal API keys
- **Alternative**: Wait and retry later

#### "Permission denied"
- **Solution**: Run as Administrator or adjust execution policy
- **Command**: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### Debug Information
- **Log file**: `debug_log.txt` contains detailed execution logs
- **Progress file**: `scan_progress.txt` shows current progress
- **Error codes**: 
  - `0`: Success
  - `1`: Configuration error
  - `2`: Runtime errors occurred

## Performance Optimization

### For Large IoC Lists
1. **Use multiple API keys** for parallel processing
2. **Batch processing** recommended for 100+ IoCs
3. **Monitor rate limits** via debug logs
4. **Consider time zones** for API quota resets

### Best Practices
- **Validate IoCs** before processing
- **Backup results** regularly
- **Monitor API quotas** to avoid rate limiting
- **Use descriptive filenames** for different scans

## Security Considerations

### API Key Security
- **Never commit API keys** to version control
- **Use environment variables** for production
- **Rotate keys regularly** for security
- **Monitor API usage** for unusual activity

### Data Handling
- **IoCs may be sensitive** - handle with care
- **Results contain threat data** - secure appropriately
- **Log files** may contain IoCs - secure access

## Contributing

### Development Setup
1. **Fork the repository**
2. **Create feature branch**
3. **Test thoroughly** with sample data
4. **Submit pull request**

### Code Standards
- **PowerShell best practices** followed
- **Error handling** required for all functions
- **Documentation** for new features
- **Testing** with various IoC types

## License

This project is designed for internal security operations. Please ensure compliance with:
- **VirusTotal Terms of Service**
- **AbuseIPDB Terms of Service**
- **Your organization's security policies**

## Support

### Getting Help
1. **Check troubleshooting section** above
2. **Review debug logs** for specific errors
3. **Validate API keys** and IoC format
4. **Test with sample data** first

### Reporting Issues
- **Include debug logs** when reporting
- **Describe expected vs actual behavior**
- **Provide sample IoCs** (sanitized)
- **Specify environment details**

---


**Note**: This tool is designed for legitimate security research and threat hunting. Ensure all usage complies with applicable laws and terms of service. 
