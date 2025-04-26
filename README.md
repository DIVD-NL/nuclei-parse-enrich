# nuclei-parse-enrich

This package can be used to parse and enrich the output of a [nuclei](https://github.com/projectdiscovery/nuclei) scan with IP geolocation, ASN information, and abuse contacts.

## Installation

```bash
# Clone the repository
git clone https://github.com/DIVD-NL/nuclei-parse-enrich.git
cd nuclei-parse-enrich

# Build the tool
go build -o nuclei-enricher cmd/main.go
```

## Usage

The tool supports multiple input methods:

- Process Nuclei JSON output with the `-i` flag
- Process a simple IP list with the `-f` flag
- Read from standard input (piped input)

### Command-Line Options

```
  -i, --input=FILE    Process a file with Nuclei scan output
  -f, --file=FILE     Process a simple IP file with one IP address per line
  -o, --output=FILE   Write enriched output to a file (default: output_TIMESTAMP.json)
  -d, --debug         Enable debug logging
```

### Examples

```bash
# Process Nuclei scan output
$ go run cmd/main.go -i /testing/nuclei-output.json

# Process an IP list
$ go run cmd/main.go -f /testing/ips_list.txt

# Use with piped input
$ cat scan.json | ./nuclei-enricher --output scan.enriched.json
```

> **Note**: When using Nuclei, use the `-json` or `-json-export FILE_LOCATION` flag to generate compatible output.

## Input Formats

The tool supports multiple formats for Nuclei output:
- JSON array of objects (with `-json` or `-json-export` flag)
- Map format (older Nuclei versions) with IP as keys
- Single JSON object per line

## Enrichment Information

The tool enriches IP addresses with the following data:

### Primary Source: RipeStat REST APIs
- ASN Number and Holder (organization name)
- Network Prefix
- Geolocation (Country, City) when available
- Abuse Contact information when available

### Fallback Sources:
1. **Whois lookup**: Used if RipeStat doesn't provide abuse contacts
2. **IPInfo**: Optional enrichment source if configured with an API token

## Environment Variables

- `IPINFO_TOKEN`: Optional API token for IPInfo service

For IPInfo support:
```bash
# Create .env file from the example
cp example.env .env
# Add your IPInfo token in the .env file
```

## Output Format

The output is a JSON file containing enriched records with both original scan data and additional IP information.

## Example nuclei output (input format)

```
[{
  "template-id": "generic-detection",
  "info": {
    "name": "Generic Detection",
    "author": ["Pepijn van der Stap"],
    "tags": ["tag1", "tag2"],
    "description": "Example vulnerability detection",
    "reference": ["https://example.com/reference"],
    "severity": "info",
    "metadata": {"max-request": 1},
    "classification": {"cve-id": null, "cwe-id": ["cwe-200"]}
  },
  "matcher-name": "generic",
  "type": "http",
  "host": "example.com",
  "port": "80",
  "scheme": "http",
  "url": "http://example.com/",
  "path": "/",
  "matched-at": "http://example.com/",
  "request": "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\nAccept-Encoding: gzip\r\n\r\n",
  "response": "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html><body>Example response</body></html>",
  "ip": "1.2.3.4",
  "timestamp": "2022-06-06T08:37:15.398363+02:00",
  "curl-command": "curl -X 'GET' -H 'Host: example.com' -H 'User-Agent: Mozilla/5.0' 'http://example.com/'",
  "matcher-status": true
}]
```

## Example output.json (enriched result)

```
{
  "1.2.3.4": {
    "Ip": "1.2.3.4",
    "AbuseSource": "ripeSTAT",
    "Abuse": "abuse@example.com",
    "Prefix": "1.2.3.0/24",
    "Asn": "1234",
    "Holder": "Example Hosting",
    "Country": "US",
    "City": "New York",
    "template-id": "generic-detection",
    "info": {
      "name": "Generic Detection",
      "author": [
        "Pepijn van der Stap"
      ],
      "tags": [
        "tag1",
        "tag2"
      ],
      "reference": [
        "https://example.com/reference"
      ],
      "severity": "info",
      "description": "Example vulnerability detection"
    },
    "type": "http",
    "host": "example.com",
    "matched-at": "http://example.com/",
    "extracted-results": null,
    "ip": "1.2.3.4",
    "timestamp": "2022-06-06T08:37:15.398363+02:00",
    "curl-command": "curl -X 'GET' -H 'Host: example.com' -H 'User-Agent: Mozilla/5.0' 'http://example.com/'",
    "matcher-status": true
  }
}
```

## Security Considerations

This tool implements several security best practices:

- **Input Validation**: All IP addresses and email addresses are validated before processing
- **Safe Regex Patterns**: Regular expressions are designed to prevent ReDoS (Regular Expression Denial of Service) attacks
- **Rate Limiting**: API requests include exponential backoff and jitter to prevent overwhelming external services
- **Error Handling**: Graceful error recovery to prevent information leakage

For security scanning and validation, we recommend running:

```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run security scanning
gosec ./...
```

## TODO

- [x] filter special characters from abuse emails (testing)
- [x] fix ReDoS vulnerabilities in regex patterns
- [ ] add comprehensive unit tests
- [ ] goreleaser

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Releasing

To release a new version of nuclei-parse-enrich, we use [goreleaser](https://goreleaser.com/).

```
# Install goreleaser (if not already installed)
go install github.com/goreleaser/goreleaser@latest

# Create and tag a new release
git tag -a v0.1.0 -m "First release"
git push origin v0.1.0

# Build and release
goreleaser release --clean
```

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
