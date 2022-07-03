package ripestat

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func ConvertAbuseContactsData(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	resp := AbuseContactFinderBase{}

	err := json.NewDecoder(bytes.NewReader(data)).Decode(&resp)

	if err != nil {
		return nil, fmt.Errorf("ConvertAbuseContactsData: failed to Unmarshal data: %v", err)
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
	err := json.NewDecoder(bytes.NewReader(data)).Decode(&resp)
	if err != nil {
		return ASOverview{}, fmt.Errorf("failed to unmarshal data: %v", err)
	}
	return resp.Data, nil
}

func ConvertGeolocationData(data []byte) (MaxmindGeoLite, error) {
	if len(data) == 0 {
		return MaxmindGeoLite{}, fmt.Errorf("empty data")
	}

	resp := MaxmindGeoLiteBase{}
	err := json.NewDecoder(bytes.NewReader(data)).Decode(&resp)
	if err != nil {
		return MaxmindGeoLite{}, fmt.Errorf("failed to unmarshal data: %v", err)
	}
	return resp.Data, nil
}
