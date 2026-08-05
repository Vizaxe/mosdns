package utils

import (
	"encoding/base64"
	"encoding/json"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/miekg/dns"
	"time"
)

const layout = "2006-01-02T15:04:05.999999999Z07:00"

type cacheItemJSON struct {
	Resp           string `json:"resp"`
	BlockHoleTag   string `json:"block_hole_tag"`
	StoredTime     string `json:"stored_time"`
	ExpirationTime string `json:"expiration_time"`
}

func Unmarshal(rawBytes []byte, r any) error {
	return json.Unmarshal(rawBytes, r)
}

func Marshal(r any) ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalItem(rawBytes []byte) *cache.Item {
	v := new(cacheItemJSON)
	if err := json.Unmarshal(rawBytes, v); err != nil {
		return nil
	}

	storedTime, err := time.Parse(layout, v.StoredTime)
	if err != nil {
		return nil
	}
	expirationTime, err := time.Parse(layout, v.ExpirationTime)
	if err != nil {
		return nil
	}

	resp := bytesToDNSMsg(v.Resp)
	if resp == nil {
		return nil
	}

	return &cache.Item{
		Resp:           resp,
		StoredTime:     storedTime,
		ExpirationTime: expirationTime,
		BlockHoleTag:   v.BlockHoleTag,
	}
}

func MarshalItem(item *cache.Item) ([]byte, error) {
	v := &cacheItemJSON{
		Resp:           dnsMsgToBase64(item.Resp),
		BlockHoleTag:   item.BlockHoleTag,
		StoredTime:     item.StoredTime.Format(layout),
		ExpirationTime: item.ExpirationTime.Format(layout),
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func dnsMsgToBase64(m *dns.Msg) string {
	b, err := m.Pack()
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func bytesToDNSMsg(data string) *dns.Msg {
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return nil
	}
	return m
}
