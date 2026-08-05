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
	"context"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// DefaultLazyUpdateTimeout 是 lazy cache 异步更新的默认超时时间。
// 与 forward 查询超时（5s）一致，避免异步 goroutine 长期存活堆积。
const DefaultLazyUpdateTimeout = time.Second * 5

// ChainExecutor 是 lazy update 中执行下一步链的接口。
// 用于避免对 sequence 包的直接依赖，打破循环引用。
type ChainExecutor interface {
	ExecNext(ctx context.Context, qCtx *query_context.Context) error
}

// LazyUpdate 执行 lazy cache 异步更新。
// 它使用 singleflight 对同一 msgKey 去重，异步执行 next 链并调用 saveResp 保存结果。
// ctx 用作异步更新 goroutine 的父 context，调用方关闭时应取消该 context 以终止残余 goroutine。
func LazyUpdate(
	ctx context.Context,
	sf *singleflight.Group,
	logger *zap.Logger,
	msgKey string,
	qCtx *query_context.Context,
	next ChainExecutor,
	saveResp func(r *dns.Msg),
) {
	qCtxCopy := qCtx.Copy()
	lazyUpdateFunc := func() (any, error) {
		defer sf.Forget(msgKey)
		qCtx := qCtxCopy

		logger.Debug("start lazy cache update", qCtx.InfoField())
		ctx, cancel := context.WithTimeout(ctx, DefaultLazyUpdateTimeout)
		defer cancel()

		err := next.ExecNext(ctx, qCtx)
		if err != nil {
			logger.Warn("failed to update lazy cache", qCtx.InfoField(), zap.Error(err))
		}

		if r := qCtx.R(); r != nil {
			saveResp(r)
		}
		logger.Debug("lazy cache updated", qCtx.InfoField())
		return nil, nil
	}
	sf.DoChan(msgKey, lazyUpdateFunc)
}
