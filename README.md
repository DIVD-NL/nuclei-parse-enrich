# nuclei-parse-enrich

This package can be used to parse and enrich the output of a [nuclei](https://github.com/projectdiscovery/nuclei) scan.

It will enrich the output with the following information:

### RipeStat REST API's:-
- ASN Number and Name
- Geolocation (Country, City) _(if available)_
- Abuse Contact _(if available))
- Prefix (as announced by the ASN)


### Whois lookup (fallback)
- Contact emails _(if available)_

It will enrich based on the IP address of the host. It mostly queries RipeStat REST APIs.
In the event that there is no Abuse Contact information, it will perform a whois lookup.

## Usage
Input gets written from standard input, unless a file is provided with the -i flag or -f flag.
By default, output gets written to output.json, but can be specified with use of the -o flag.

For ipinfo support, replace example.env to .env and add your ipinfo token to the ipinfo_token variable.

`$ go get github.com/ipinfo/go/v2/ipinfo`


#### Example Usage

> make sure you ran nuclei with -json flag

`$ go run cmd/main.go -i /opt/nuclei-output.json`

`$ go run cmd/main.go -f /opt/ips_list.txt`

`$ go build cmd/main.go -o nuclei-enricher`

`$ cp scan.json /dev/stdin | ./nuclei-enricher --output scan.enriched.json`



## Example output.json

```

{
  "1.2.3.4": {
    "Ip": "1.2.3.4",
    "AbuseSource": "ripeSTAT",
    "Abuse": "info@domain.tld",
    "Prefix": "1.2.3.4/32",
    "Asn": "1234",
    "Holder": "some hosting",
    "Country": "NL",
    "City": "some city",
    "template-id": "title-extract",
    "info": {
      "name": "title-extract",
      "author": [
        "xstp"
      ],
      "tags": [
        "title"
      ],
      "reference": null,
      "severity": "info",
      "description": ""
    },
    "type": "http",
    "host": "http://localhost/test",
    "matched-at": "http://localhost/test",
    "extracted-results": null,
    "ip": "1.2.3.4",
    "timestamp": "2022-06-06T08:37:15.398363+02:00",
    "curl-command": "curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: some-user-agent' 'http://divd.nl/test'",
    "matcher-status": true,
    "matched-line": ""
  }
}

```


## TODO

- [ ] Don't enrich ips from a netblock more than once
- [ ] Add IpInfo as a fallback
- [ ] filter special characters from abuse emails (testing)
- [ ] goreleaser
