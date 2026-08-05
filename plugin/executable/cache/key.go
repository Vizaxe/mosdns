/*
 * Copyright (C) 2024, Vizaxe
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package cache

import (
	"strings"
	"unsafe"

	"github.com/miekg/dns"
)

// MsgQuestionKey 返回 DNS 问题的规范化 key 字符串。
// 格式: [prefix + separator + ]TypeStr + separator + ClassStr + separator + Name
// name 会被转为小写以保证大小写不敏感的一致性。
// 使用 unsafe 零拷贝转换减少内存分配。
func MsgQuestionKey(q *dns.Msg, separator, prefix string) string {
	if len(q.Question) == 0 {
		return ""
	}
	question := q.Question[0]
	typeStr := dns.TypeToString[question.Qtype]
	classStr := dns.ClassToString[question.Qclass]
	name := strings.ToLower(question.Name)

	totalLen := len(typeStr) + len(separator) + len(classStr) + len(separator) + len(name)
	if len(prefix) > 0 {
		totalLen += len(prefix) + len(separator)
	}

	buf := make([]byte, totalLen)
	n := 0
	if len(prefix) > 0 {
		n += copy(buf[n:], prefix)
		n += copy(buf[n:], separator)
	}
	n += copy(buf[n:], typeStr)
	n += copy(buf[n:], separator)
	n += copy(buf[n:], classStr)
	n += copy(buf[n:], separator)
	n += copy(buf[n:], name)

	return unsafe.String(unsafe.SliceData(buf), len(buf))
}
