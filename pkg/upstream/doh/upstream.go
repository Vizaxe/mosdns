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

package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	defaultDoHTimeout = time.Second * 6

	// maxGetURLLen is the maximum length of the GET request URL query string.
	// If the base64-encoded DNS query exceeds this length, POST method will be used
	// to avoid "414 Request-URI Too Large" errors from some DoH servers (e.g. Google).
	// RFC 8484 allows both GET and POST; POST has no URL length limitation.
	maxGetURLLen = 2000
)

var nopLogger = zap.NewNop()

// Upstream is a DNS-over-HTTPS (RFC 8484) upstream.
type Upstream struct {
	rt          http.RoundTripper
	logger      *zap.Logger // non-nil
	urlTemplate *urlpkg.URL
	reqTemplate *http.Request
}

func NewUpstream(endPoint string, ua string, rt http.RoundTripper, logger *zap.Logger) (*Upstream, error) {
	req, err := http.NewRequest(http.MethodGet, endPoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse http request, %w", err)
	}

	req.Header["Accept"] = []string{"application/dns-message"}
	req.Header["User-Agent"] = []string{ua} // Don't let go http send a default user agent header.

	if logger == nil {
		logger = nopLogger
	}
	return &Upstream{
		rt:          rt,
		logger:      logger,
		urlTemplate: req.URL,
		reqTemplate: req,
	}, nil
}

var (
	bufPool4k = pool.NewBytesBufPool(4096)
)

func (u *Upstream) ExchangeContext(ctx context.Context, q []byte) (*[]byte, error) {
	bp := pool.GetBuf(len(q))
	defer pool.ReleaseBuf(bp)
	wire := *bp
	copy(wire, q)

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484#section-4.1
	wire[0] = 0
	wire[1] = 0

	queryLen := 4 + base64.RawURLEncoding.EncodedLen(len(wire))

	// Use parent context with at least defaultDoHTimeout.
	// For HTTP/2 (which DoH uses), cancelling a request context only
	// RST_STREAMs the single stream, NOT the entire connection.
	// So connection reuse is preserved.
	dohCtx, cancel := context.WithTimeout(ctx, defaultDoHTimeout)
	defer cancel()

	var r *[]byte
	var err error
	if queryLen > maxGetURLLen {
		// Use POST for large queries to avoid "414 Request-URI Too Large".
		body := make([]byte, len(wire))
		copy(body, wire)
		r, err = u.exchangePost(dohCtx, body)
	} else {
		queryBuf := make([]byte, queryLen)
		p := 0
		p += copy(queryBuf, "dns=")

		// Padding characters for base64url MUST NOT be included.
		// See: https://tools.ietf.org/html/rfc8484#section-6.
		base64.RawURLEncoding.Encode(queryBuf[p:], wire)
		r, err = u.exchange(dohCtx, utils.BytesToStringUnsafe(queryBuf))
	}

	if err != nil {
		u.logger.Check(zap.WarnLevel, "exchange failed").Write(zap.Error(err))
	}
	if r != nil {
		binary.BigEndian.PutUint16(*r, binary.BigEndian.Uint16(q))
	}
	return r, err
}

func (u *Upstream) exchange(ctx context.Context, dnsQuery string) (*[]byte, error) {
	req := u.reqTemplate.WithContext(ctx)
	req.URL = new(urlpkg.URL)
	*req.URL = *u.urlTemplate
	req.URL.RawQuery = dnsQuery
	return u.doHTTPRequest(ctx, req)
}

func (u *Upstream) exchangePost(ctx context.Context, body []byte) (*[]byte, error) {
	req := u.reqTemplate.WithContext(ctx)
	req.Method = http.MethodPost
	req.URL = new(urlpkg.URL)
	*req.URL = *u.urlTemplate
	req.URL.RawQuery = ""
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/dns-message")
	return u.doHTTPRequest(ctx, req)
}

func (u *Upstream) doHTTPRequest(ctx context.Context, req *http.Request) (*[]byte, error) {
	resp, err := u.rt.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode != http.StatusOK {
		body1k, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if body1k != nil {
			return nil, fmt.Errorf("bad http status codes %d with body [%s]", resp.StatusCode, body1k)
		}
		return nil, fmt.Errorf("bad http status codes %d", resp.StatusCode)
	}

	bb := bufPool4k.Get()
	defer bufPool4k.Release(bb)
	_, err = bb.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read http body: %w", err)
	}
	if bb.Len() < dnsutils.DnsHeaderLen {
		return nil, dnsutils.ErrPayloadTooSmall
	}
	payload := pool.GetBuf(bb.Len())
	copy(*payload, bb.Bytes())
	return payload, nil
}
