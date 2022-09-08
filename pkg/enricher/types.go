package enricher

import (
	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/ipinfo"
	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/ripestat"
	"regexp"
)

var whoisRegexp = regexp.MustCompile("[a-zA-Z\\d.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z\\d](?:[a-zA-Z\\d-]{0,61}[a-zA-Z\\d])?(?:\\.[a-zA-Z\\d](?:[a-zA-Z\\d-]{0,61}[a-zA-Z\\d])?)*\\.?[a-zA-Z\\d](?:[a-zA-Z\\d-]{0,61}[a-zA-Z\\d])?(?:\\.[a-zA-Z\\d](?:[a-zA-Z\\d-]{0,61}[a-zA-Z\\d])?)*")

const (
	RipeStatSourceApp = "AS50559-DIVD_NL"
)

type Enricher struct {
	rs *ripestat.Client
	io *ipinfo.Client
}
