package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// Paths served by the in-process upstream.
const (
	pathSmall = "/products/list" // any path other than pathLarge returns the 1 KB page
	pathLarge = "/page50k"
)

// htmlPage returns a deterministic, valid HTML document of exactly size bytes.
func htmlPage(size int, title string) []byte {
	var b bytes.Buffer
	head := "<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\"><title>" + title + "</title></head><body><main>\n"
	tail := "</main></body></html>\n"
	b.WriteString(head)
	for i := 0; b.Len() < size-len(tail)-64; i++ {
		fmt.Fprintf(&b, "<p class=\"item\">Sản phẩm số %d – mô tả ngắn gọn cho trang thử tải.</p>\n", i)
	}
	for b.Len() < size-len(tail) {
		b.WriteByte(' ')
	}
	b.WriteString(tail)
	return b.Bytes()
}

// upstream is a minimal, fast origin server: fixed bodies, no allocation per
// request beyond what net/http needs.
type upstream struct {
	srv      *http.Server
	ln       net.Listener
	newConns atomic.Int64 // TCP connections accepted (keep-alive efficiency)
	small    []byte
	large    []byte
}

func startUpstream(addr string) (*upstream, error) {
	u := &upstream{small: htmlPage(1024, "1KB"), large: htmlPage(50*1024, "50KB")}
	smallLen, largeLen := strconv.Itoa(len(u.small)), strconv.Itoa(len(u.large))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		body, n := u.small, smallLen
		if r.URL.Path == pathLarge {
			body, n = u.large, largeLen
		}
		hd := w.Header()
		hd["Content-Type"] = []string{"text/html; charset=utf-8"}
		hd["Content-Length"] = []string{n}
		_, _ = w.Write(body)
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("upstream listen %s: %w", addr, err)
	}
	u.ln = ln
	u.srv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				u.newConns.Add(1)
			}
		},
	}
	go func() { _ = u.srv.Serve(ln) }()
	return u, nil
}

func (u *upstream) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = u.srv.Shutdown(ctx)
}
