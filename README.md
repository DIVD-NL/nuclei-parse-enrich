## nuclei-parse-enrich

This package provides a parser for nuclei's json output files.

It will then enrich the data with additional information from the RipeStat REST API,
in case it doesn't return a abuse contact we perform a whois lookup and parse the email addresses.

Input gets written from standard input, unless a file is provided with the -i flag.

By default, output gets written to output.csv, but can be specified with use of the -o flag.

## Example Usage

> make sure you ran nuclei with -json flag

`$ go build cmd/main.go && scp -i ~/.ssh/id_ed25519 xstp@testing:/home/xstp/28-05-2022.test.json /dev/stdin | ./main --output 28-05-2022-test.enriched.csv`

`$ go run cmd/main.go -i /opt/nuclei-output.json`


## Example output.csv

```

'TemplateId','Info','Type','Host','MatchedAt','ExtractedResults','Ip','Timestamp','CurlCommand','MatcherStatus','MatchedLine','Abuse_source','Abuse','Prefix','Asn','Holder','Country','City'
'test',"'{""name"":""test template"",""author"":[""xstp""],""tags"":[""test""],""reference"":"""",""severity"":""info"",""description"":""""}'",'http','https://test:443','https://test:443/test','cf1698b892d00074274847d89936aaaf: command not found','0.0.0.0','2022-05-24T15:27:37.073351768+02:00',"'curl -X 'GET' -d '' -H 'Accept: application/json, text/plain, */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Host: test:443' -H 'Referer: https://test:443' -H 'User-Agent: DIVD scan for case 2022-00000 - See https://csirt.divd.nl/' 'https://test:443/test''",'true','','ripeSTAT','support@demo.net;abuse-mail@demo.net','0.0.0.0/32','1337','DIVD','NL'

```


## TODO

- [ ] bug: empty fields may miss in csv output
- [ ] Add and test thread safe goroutine workers for ripeStat and enrichment in general
- [ ] Don't enrich ips from a netblock more than once
- [ ] If 'Ip' key is hostname, dig short hostname - if it returns multiple, match ipv4 and ipv6 regexp, return 0th element
