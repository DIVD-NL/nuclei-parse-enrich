package ipinfo

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"github.com/ipinfo/go/v2/ipinfo"
	"os"
)

type Client struct {
	*ipinfo.Client
	MaxRetries int
}

func NewIpInfoClient(maxRetries int) *Client {
	if maxRetries == 0 {
		maxRetries = 3
	}

	return &Client{
		Client:     ipinfo.NewClient(nil, nil, os.Getenv("IPINFO_TOKEN")),
		MaxRetries: maxRetries,
	}
}
