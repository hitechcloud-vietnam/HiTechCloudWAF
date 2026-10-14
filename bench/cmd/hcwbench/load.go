package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// request describes what one client sends. Requests are rebuilt for every
// call from these immutable parts so that clients share nothing mutable.
type request struct {
	method string
	path   string // path and query
	host   string
	header http.Header
	body   []byte
}

// loadSpec is one closed-loop run: every client sends a request, waits for
// the full response and immediately sends the next one.
type loadSpec struct {
	target  string // "127.0.0.1:port"
	clients int
	warmup  time.Duration
	measure time.Duration
	next    func(n uint64) request // n is a global request counter
	expect  []int                  // expected statuses; anything else is an error
	// onWindow is called at the start and the end of the measured window
	// (used to sample engine CPU time exactly over that window).
	onWindow func(start bool)
}

type loadResult struct {
	Requests   int64
	Errors     int64
	Duration   time.Duration
	RPS        float64
	P50, P90   time.Duration
	P99, Max   time.Duration
	BytesRead  int64
	FirstError string
}

func newClient(clients int) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:               nil, // ignore HTTP(S)_PROXY: all traffic is local
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:        clients * 2,
			MaxIdleConnsPerHost: clients * 2,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
		},
	}
}

func runLoad(ctx context.Context, s loadSpec) loadResult {
	client := newClient(s.clients)
	defer client.CloseIdleConnections()

	var counter atomic.Uint64
	t0 := time.Now()
	winStart := t0.Add(s.warmup)
	winEnd := winStart.Add(s.measure)

	// Sample the window boundaries from a dedicated goroutine so that the
	// samples are taken on time regardless of what the clients are doing.
	var wg sync.WaitGroup
	if s.onWindow != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-time.After(time.Until(winStart)):
				s.onWindow(true)
			case <-ctx.Done():
				return
			}
			select {
			case <-time.After(time.Until(winEnd)):
			case <-ctx.Done():
			}
			s.onWindow(false)
		}()
	}

	type worker struct {
		lat      []time.Duration
		errs     int64
		bytes    int64
		firstErr string
	}
	workers := make([]*worker, s.clients)
	for i := range workers {
		w := &worker{lat: make([]time.Duration, 0, 1<<15)}
		workers[i] = w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				start := time.Now()
				if !start.Before(winEnd) {
					return
				}
				rq := s.next(counter.Add(1))
				var body io.Reader
				if rq.body != nil {
					body = bytes.NewReader(rq.body)
				}
				req, err := http.NewRequestWithContext(ctx, rq.method, "http://"+s.target+rq.path, body)
				if err != nil {
					panic(err)
				}
				req.Host = rq.host
				for k, v := range rq.header {
					req.Header[k] = v
				}
				resp, err := client.Do(req)
				status := 0
				var n int64
				if err == nil {
					n, err = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					status = resp.StatusCode
				}
				d := time.Since(start)
				if !start.Before(winStart) {
					w.lat = append(w.lat, d)
					w.bytes += n
					if err != nil || !slices.Contains(s.expect, status) {
						w.errs++
						if w.firstErr == "" {
							if err != nil {
								w.firstErr = err.Error()
							} else {
								w.firstErr = "unexpected status " + http.StatusText(status)
							}
						}
					}
				}
				if err != nil {
					// Do not spin on a dead target.
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()

	var all []time.Duration
	var res loadResult
	for _, w := range workers {
		all = append(all, w.lat...)
		res.Errors += w.errs
		res.BytesRead += w.bytes
		if res.FirstError == "" {
			res.FirstError = w.firstErr
		}
	}
	res.Requests = int64(len(all))
	res.Duration = s.measure
	res.RPS = float64(res.Requests) / s.measure.Seconds()
	if len(all) > 0 {
		sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
		q := func(p float64) time.Duration { return all[min(len(all)-1, int(p*float64(len(all))))] }
		res.P50, res.P90, res.P99, res.Max = q(0.50), q(0.90), q(0.99), all[len(all)-1]
	}
	return res
}
