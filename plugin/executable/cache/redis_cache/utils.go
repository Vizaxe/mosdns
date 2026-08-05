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

package redis_cache

import (
	"github.com/IrineSistiana/mosdns/v5/pkg/cache_backend"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/miekg/dns"
)

var _ cache.Cache[cache_backend.StringKey, string] = (*RedisCache)(nil)

func getMsgKey(q *dns.Msg, separator string, prefix string) string {
	return cache.MsgQuestionKey(q, separator, prefix)
}
