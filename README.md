## nuclei-parse-enrich

This package provides a parser for nuclei's json output files.

It will then enrich the data with additional information from the RipeStat REST API,
in case it doesn't return a abuse contact we perform a whois lookup and parse the email addresses.

Input gets written from standard input, unless a file is provided with the -i flag.

By default, output gets written to output.json, but can be specified with use of the -o flag.

## Example Usage

> make sure you ran nuclei with -json flag

`$ go build cmd/main.go && scp -i ~/.ssh/id_ed25519 xstp@testing:/home/xstp/28-05-2022.test.json /dev/stdin | ./main --output 28-05-2022-test.enriched.json`

`$ go run cmd/main.go -i /opt/nuclei-output.json`


## Example output.json

```

{
    "localhost": {
      "Ip": "localhost",
      "Abuse_source": "ripeSTAT",
      "Abuse": "abuse-mail@demo.net;abuse@demo.net",
      "Prefix": "0.0.0.0/32",
      "Asn": "1337",
      "Holder": "DIVD",
      "Country": "NL",
      "City": "city",
      "template-id": "test",
      "info": {
        "name": "test",
        "author": [
          "xstp"
        ],
        "tags": [
          "test"
        ],
        "reference": "",
        "severity": "info",
        "description": ""
      },
      "type": "http",
      "host": "https://localhost:443",
      "matched-at": "https://localhost:443/test",
      "extracted-results": [
        "test"
      ],
      "ip": "localhost",
      "timestamp": "2022-05-24T15:27:37.073351768+02:00",
      "curl-command": "curl -X 'GET' -d '' -H 'Accept: application/json, text/plain, */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Host: localhost:443' -H 'Referer: https://localhost:443' -H 'User-Agent: DIVD scan for case 2022-00000 - See https://csirt.divd.nl/' 'https://localhost:443/test'",
      "matcher-status": true,
      "matched-line": ""
    },
}

```


## TODO

- [ ] Add and test thread safe goroutine workers for ripeStat and enrichment in general
- [ ] Don't enrich ips from a netblock more than once
- [ ] If 'Ip' key is hostname, dig short hostname - if it returns multiple, match ipv4 and ipv6 regexp, return 0th element
