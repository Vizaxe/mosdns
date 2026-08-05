/*
 * Copyright (C) 2020-2022, IrineSistiana
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

package has_dot

import (
	"context"
	"fmt"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

const PluginType = "has_dot"

func init() {
	sequence.MustRegMatchQuickSetup(PluginType, QuickSetup)
}

func QuickSetup(_ sequence.BQ, s string) (sequence.Matcher, error) {
	matchHasDot := true
	switch strings.TrimSpace(s) {
	case "false", "no", "0", "not":
		matchHasDot = false
	case "true", "yes", "1", "":
		matchHasDot = true
	default:
		return nil, fmt.Errorf("invalid arg %q, expect true/false", s)
	}
	return sequence.MatchFunc(func(_ context.Context, qCtx *query_context.Context) (bool, error) {
		name := qCtx.QQuestion().Name
		name = strings.TrimSuffix(name, ".")
		hasDot := strings.Contains(name, ".")
		return hasDot == matchHasDot, nil
	}), nil
}
