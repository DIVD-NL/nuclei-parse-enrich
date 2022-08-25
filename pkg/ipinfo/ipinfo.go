package ipinfo

import (
	"fmt"
	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/sirupsen/logrus"
	"net"
	"os"
)

func Test() string {
	client := ipinfo.NewClient(nil, nil, os.Getenv("IPINFO_TOKEN"))
	info, err := client.GetIPInfo(net.ParseIP("194.5.73.0"))
	if err != nil {
		logrus.Fatal(err)
	}

	return fmt.Sprintf("%+v", info)
}
