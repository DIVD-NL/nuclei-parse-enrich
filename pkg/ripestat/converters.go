package ripestat

import (
	"encoding/json"
	"fmt"
)

func ConvertAbuseContactsData(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	resp := AbuseContactFinderBase{}
	err := json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Data.AbuseContacts, nil
}

func ConvertNetworkInfoData(data []byte) (NetworkInfo, error) {
	if len(data) == 0 {
		return NetworkInfo{}, fmt.Errorf("empty data")
	}

	resp := NetworkInfoBase{}
	err := json.Unmarshal(data, &resp)
	if err != nil {
		return NetworkInfo{}, err
	}
	return resp.Data, nil
}

func ConvertASOverviewData(data []byte) (ASOverview, error) {
	if len(data) == 0 {
		return ASOverview{}, fmt.Errorf("empty data")
	}

	resp := ASOverviewBase{}
	err := json.Unmarshal(data, &resp)
	if err != nil {
		return ASOverview{}, err
	}
	return resp.Data, nil
}
