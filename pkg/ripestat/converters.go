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
