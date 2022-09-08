package ipinfo

import (
	"github.com/ipinfo/go/v2/ipinfo"
	"net"
	"os"
)

type Client struct {
	MaxRetries int
}

//
//func Test() string {
//	client := ipinfo.NewClient(nil, nil, os.Getenv("IPINFO_TOKEN"))
//	info, err := client.GetIPInfo(net.ParseIP("194.5.73.0"))
//	if err != nil {
//		logrus.Fatal(err)
//	}
//
//	return fmt.Sprintf("%+v", info)
//}

func NewIpInfoClient() *ipinfo.Client {
	return ipinfo.NewClient(nil, nil, os.Getenv("IPINFO_TOKEN"))
}

func (c *Client) GetIPInfo(ip net.IP) (*ipinfo.IPInfo, error) {
	return c.Client.GetIPInfo(ip)
}
