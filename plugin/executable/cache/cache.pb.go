// Code generated manually. DO NOT EDIT.
// source: plugin/executable/cache/cache.proto
//
// 由于环境中没有 protoc，使用 protowire 手写序列化/反序列化。

package cache

import (
	"google.golang.org/protobuf/encoding/protowire"
)

// CachedEntry 是统一的缓存条目，用于 Redis 缓存存储和 memory_cache dump。
// DNS 消息以 wire format（Pack/Unpack）存储在 Msg 字段中。
type CachedEntry struct {
	Msg                 []byte
	StoredTime          int64
	ExpirationTime      int64
	BlockHoleTag        string
	Key                 []byte // dump 文件需要持久化 key；Redis 中 key 是 Redis key，此字段为空
	CacheExpirationTime int64  // 缓存条目过期时间（lazy cache 时可能与消息过期时间不同）；Redis 中由 Redis TTL 管理，此字段为空
}

// Marshal 将 CachedEntry 序列化为 protobuf 二进制格式。
func (x *CachedEntry) Marshal() ([]byte, error) {
	var b []byte
	if len(x.Msg) > 0 {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, x.Msg)
	}
	if x.StoredTime != 0 {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(x.StoredTime))
	}
	if x.ExpirationTime != 0 {
		b = protowire.AppendTag(b, 3, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(x.ExpirationTime))
	}
	if len(x.BlockHoleTag) > 0 {
		b = protowire.AppendTag(b, 4, protowire.BytesType)
		b = protowire.AppendString(b, x.BlockHoleTag)
	}
	if len(x.Key) > 0 {
		b = protowire.AppendTag(b, 5, protowire.BytesType)
		b = protowire.AppendBytes(b, x.Key)
	}
	if x.CacheExpirationTime != 0 {
		b = protowire.AppendTag(b, 6, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(x.CacheExpirationTime))
	}
	return b, nil
}

// Unmarshal 从 protobuf 二进制格式反序列化 CachedEntry。
func (x *CachedEntry) Unmarshal(data []byte) error {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		switch num {
		case 1: // msg
			v, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			x.Msg = append([]byte(nil), v...)
			data = data[m:]
		case 2: // stored_time
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			x.StoredTime = int64(v)
			data = data[m:]
		case 3: // expiration_time
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			x.ExpirationTime = int64(v)
			data = data[m:]
		case 4: // block_hole_tag
			v, m := protowire.ConsumeString(data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			x.BlockHoleTag = v
			data = data[m:]
		case 5: // key
			v, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			x.Key = append([]byte(nil), v...)
			data = data[m:]
		case 6: // cache_expiration_time
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			x.CacheExpirationTime = int64(v)
			data = data[m:]
		default:
			m := protowire.ConsumeFieldValue(num, typ, data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			data = data[m:]
		}
	}
	return nil
}

func (x *CachedEntry) Reset() { *x = CachedEntry{} }

// CacheDumpBlock 是 memory_cache dump 文件的分块格式。
type CacheDumpBlock struct {
	Entries []*CachedEntry
}

func (x *CacheDumpBlock) Marshal() ([]byte, error) {
	var b []byte
	for _, e := range x.Entries {
		data, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, data)
	}
	return b, nil
}

func (x *CacheDumpBlock) Unmarshal(data []byte) error {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		switch num {
		case 1:
			v, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			e := &CachedEntry{}
			if err := e.Unmarshal(v); err != nil {
				return err
			}
			x.Entries = append(x.Entries, e)
			data = data[m:]
		default:
			m := protowire.ConsumeFieldValue(num, typ, data)
			if m < 0 {
				return protowire.ParseError(m)
			}
			data = data[m:]
		}
	}
	return nil
}

func (x *CacheDumpBlock) Reset() { *x = CacheDumpBlock{} }

func (x *CacheDumpBlock) GetEntries() []*CachedEntry {
	if x != nil {
		return x.Entries
	}
	return nil
}
