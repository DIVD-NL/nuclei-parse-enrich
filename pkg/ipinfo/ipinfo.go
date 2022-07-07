package ipinfo

type IPInfo struct {
	authToken string
}

func (i *IPInfo) NewIpInfoClient(authToken string) *IPInfo {
	return &IPInfo{
		authToken: authToken,
	}
}
