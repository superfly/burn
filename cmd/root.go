package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/montanaflynn/stats"
	"github.com/olekukonko/tablewriter"

	"github.com/abiosoft/semaphore"

	"github.com/logrusorgru/aurora"
)

func init() {
	flags := RootCmd.Flags()

	RootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	flags.IntP("concurrency", "c", 10, "number of concurrent requests")
	flags.StringP("duration", "d", "60s", "duration for the test")

	flags.BoolP("insecure-skip-verify", "k", true, "allow insecure TLS certificates (self-signed, wrong hostname, etc. default: true)")
	flags.Bool("disable-keepalives", false, "disable reusing connections via keepalives (default: false)")
	flags.Bool("resume-tls", false, "allow resuming TLS (default: false)")

	flags.StringArrayP("header", "H", []string{}, "headers to send")

}

func Execute() {
	RootCmd.Execute()
}

var timeSpent time.Duration

var (
	connectTimes      = NewConcurrentFloat64Slice()
	tlsHandshakeTimes = NewConcurrentFloat64Slice()
	ttfb              = NewConcurrentFloat64Slice()
	responseTimes     = NewConcurrentFloat64Slice()
	requestTimes      = NewConcurrentFloat64Slice()
	requestsCount     int64

	tlsCiphersUsed = NewConcurrentUint16Slice()
	tlsReusedCount int64

	errors   = NewConcurrentErrorSlice()
	statuses = NewConcurrentIntSlice()
)

var RootCmd = &cobra.Command{
	Use:   "burn [url]",
	Short: "Burn is an HTTP load tester with advanced statistics.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		flags := cmd.Flags()

		c, err := flags.GetInt("concurrency")
		if err != nil {
			panic(err)
		}

		d, err := flags.GetString("duration")
		if err != nil {
			panic(err)
		}

		dur, err := time.ParseDuration(d)
		if err != nil {
			panic(err)
		}

		u, err := url.Parse(args[0])
		if err != nil {
			panic(err)
		}

		timeout := time.After(dur)
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt)

		cancel := make(chan struct{})

		var start time.Time

		sem := semaphore.New(c)

		transport := getTransport(cmd)

		header := make(http.Header)

		headers, err := flags.GetStringArray("header")
		if err != nil {
			panic(err)
		}

		for _, h := range headers {
			parts := strings.Split(h, ":")
			header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}

		req := &http.Request{
			URL:    u,
			Header: header,
		}

		if host := header.Get("Host"); host != "" {
			req.Host = host
		}

		fmt.Printf("\n%s %s for %s\n", aurora.Red("Burning"), u, aurora.Bold(d))

		go func() {
			start = time.Now()
			for {
				sem.Acquire()
				go func() {
					var reqStart time.Time
					defer sem.Release()
					defer func() {
						go responseTimes.Append(time.Since(reqStart).Seconds())
					}()

					ctx := httptrace.WithClientTrace(context.Background(), getClientTracer())
					reqStart = time.Now()
					res, err := transport.RoundTrip(req.WithContext(ctx))
					go atomic.AddInt64(&requestsCount, 1)
					if err != nil {
						go errors.Append(err)
						return
					}
					go statuses.Append(res.StatusCode)

					if res.Body != nil {
						if _, err := io.Copy(ioutil.Discard, res.Body); err != nil {
							go errors.Append(err)
						}
						if err := res.Body.Close(); err != nil {
							go errors.Append(err)
						}
					}

				}()
			}
		}()

		select {
		case <-timeout:
			break
		case <-sigs:
			break
		case <-cancel:
			fmt.Println("Burn cancelled!")
			break
		}

		timeSpent = time.Since(start)

		time.Sleep(100 * time.Millisecond)

		fmt.Println(aurora.Green("\nStatistical Analysis:"))
		renderStats()

		fmt.Println(aurora.Cyan("\nMeta:"))
		renderMeta()

		if len(tlsCiphersUsed.GetItems()) > 0 {
			fmt.Println(aurora.Blue("\nCiphers:"))
			ciphersCount := map[string]int64{}
			for _, cipher := range tlsCiphersUsed.GetItems() {
				ciphersCount[tlsCiphersList[cipher]] = ciphersCount[tlsCiphersList[cipher]] + 1
			}
			for n, count := range ciphersCount {
				fmt.Printf("%s => %d\n", n, count)
			}
		}

		fmt.Println(aurora.Red("\nStatus code:"))
		statusCount := map[int]int64{}
		for _, s := range statuses.GetItems() {
			statusCount[s] = statusCount[s] + 1
		}

		for n, count := range statusCount {
			fmt.Printf("%d => %d\n", n, count)
		}

		fmt.Println(aurora.Red("\nErrors:"))
		fmt.Printf("%d errors.\n", len(errors.GetItems()))
		// if len(errors.GetItems()) > 0 {
		errorsCount := map[string]int64{}
		for _, err := range errors.GetItems() {
			errorsCount[err.Error()] = errorsCount[err.Error()] + 1
		}

		for n, count := range errorsCount {
			fmt.Printf("%s => %d\n", n, count)
		}
		// }

		fmt.Println("")

		os.Exit(0)
	},
}

func renderStats() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoFormatHeaders(false)
	table.SetHeader([]string{"Metric", "p50", "p75", "p95", "p99", "Min", "Mean", "Max", "Std. Dev"})
	table.SetHeaderColor(nil, nil, nil, nil, nil, nil, nil, nil, tablewriter.Color(tablewriter.FgHiBlackColor))
	table.SetColumnColor(nil, nil, nil, nil, nil, nil, nil, nil, tablewriter.Color(tablewriter.FgHiBlackColor))

	m := map[int]string{
		0: "Connect",
		1: "TLS Handshake",
		2: "Request fully written",
		3: "Response fully read",
	}

	var keys []int
	for k := range m {
		keys = append(keys, k)
	}

	csm := map[string]*ConcurrentFloat64Slice{
		"Connect":               connectTimes,
		"TLS Handshake":         tlsHandshakeTimes,
		"Request fully written": requestTimes,
		"Response fully read":   responseTimes,
	}

	sort.Ints(keys)

	for _, k := range keys {
		name := m[k]
		cs := csm[name]
		d := []string{name}
		if len(cs.GetItems()) == 0 {
			continue
		}

		for _, p := range []int{50, 75, 95, 99} {
			if pf, err := stats.Percentile(cs.GetItems(), float64(p)); err != nil {
				panic(err)
			} else {
				ps := fmt.Sprintf("%f", pf)
				if pd, err := time.ParseDuration(ps + "s"); err != nil {
					panic(err)
				} else {
					d = append(d, pd.String())
				}
			}
		}

		if min, err := stats.Min(cs.GetItems()); err != nil {
			panic(err)
		} else {
			mins := fmt.Sprintf("%f", min)
			if mind, err := time.ParseDuration(mins + "s"); err != nil {
				panic(err)
			} else {
				d = append(d, mind.String())
			}
		}

		if mean, err := stats.Mean(cs.GetItems()); err != nil {
			panic(err)
		} else {
			means := fmt.Sprintf("%f", mean)
			if meand, err := time.ParseDuration(means + "s"); err != nil {
				panic(err)
			} else {
				d = append(d, meand.String())
			}
		}

		if max, err := stats.Max(cs.GetItems()); err != nil {
			panic(err)
		} else {
			maxs := fmt.Sprintf("%f", max)
			if maxd, err := time.ParseDuration(maxs + "s"); err != nil {
				panic(err)
			} else {
				d = append(d, maxd.String())
			}
		}

		if stddev, err := stats.StandardDeviation(cs.GetItems()); err != nil {
			panic(err)
		} else {
			stddevs := fmt.Sprintf("%f", stddev)
			if stddevd, err := time.ParseDuration(stddevs + "s"); err != nil {
				panic(err)
			} else {
				d = append(d, stddevd.String())
			}
		}
		table.Append(d)
	}

	table.Render() // Send output
}

func renderMeta() {
	data := [][]string{
		[]string{"Requests Count", fmt.Sprintf("%d", requestsCount)},
		[]string{"Time spent", timeSpent.String()},
		[]string{"RPS", fmt.Sprintf("%f", float64(requestsCount)/timeSpent.Seconds())},
		[]string{"TLS Resumed", fmt.Sprintf("%d", atomic.LoadInt64(&tlsReusedCount))},
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetBorder(false) // Set Border to false
	table.AppendBulk(data) // Add Bulk Data
	table.Render()
}

func getTransport(cmd *cobra.Command) *http.Transport {
	c, err := cmd.Flags().GetInt("concurrency")
	if err != nil {
		panic(err)
	}

	insecureSkipVerify, err := cmd.Flags().GetBool("insecure-skip-verify")
	if err != nil {
		panic(err)
	}

	disableKeepalives, err := cmd.Flags().GetBool("disable-keepalives")
	if err != nil {
		panic(err)
	}

	return &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second, // I guess?
		ResponseHeaderTimeout: 60 * time.Second,

		DisableKeepAlives:   disableKeepalives,
		MaxIdleConns:        1024,  // arbitrary
		MaxIdleConnsPerHost: c * 2, // as many as we want to concurrently run

		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			DualStack: true,
		}).DialContext,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			ClientSessionCache: tls.NewLRUClientSessionCache(1024 * 10),
		},
	}
}

func getClientTracer() *httptrace.ClientTrace {
	var (
		connectStart time.Time
		tlsStart     time.Time
		reqStart     time.Time
	)

	return &httptrace.ClientTrace{
		// GetConn: func(hostPort string) {
		// },
		GotConn: func(info httptrace.GotConnInfo) {
			reqStart = time.Now()
		},
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			go connectTimes.Append(time.Since(connectStart).Seconds())
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(connState tls.ConnectionState, err error) {
			go tlsHandshakeTimes.Append(time.Since(tlsStart).Seconds())
			go tlsCiphersUsed.Append(connState.CipherSuite)
			if connState.DidResume {
				go atomic.AddInt64(&tlsReusedCount, 1)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			go requestTimes.Append(time.Since(reqStart).Seconds())
		},
	}
}

type ConcurrentFloat64Slice struct {
	sync.RWMutex
	items []float64
}

func NewConcurrentFloat64Slice() *ConcurrentFloat64Slice {
	return &ConcurrentFloat64Slice{items: make([]float64, 0)}
}

func (cs *ConcurrentFloat64Slice) Append(f float64) {
	cs.Lock()
	defer cs.Unlock()

	cs.items = append(cs.items, f)
}

func (cs *ConcurrentFloat64Slice) GetItems() []float64 {
	cs.RLock()
	defer cs.RUnlock()
	return cs.items
}

type ConcurrentErrorSlice struct {
	sync.RWMutex
	items []error
}

func NewConcurrentErrorSlice() *ConcurrentErrorSlice {
	return &ConcurrentErrorSlice{items: make([]error, 0)}
}

func (cs *ConcurrentErrorSlice) Append(f error) {
	cs.Lock()
	defer cs.Unlock()

	cs.items = append(cs.items, f)
}

func (cs *ConcurrentErrorSlice) GetItems() []error {
	cs.RLock()
	defer cs.RUnlock()
	return cs.items
}

type ConcurrentIntSlice struct {
	sync.RWMutex
	items []int
}

func NewConcurrentIntSlice() *ConcurrentIntSlice {
	return &ConcurrentIntSlice{items: make([]int, 0)}
}

func (cs *ConcurrentIntSlice) Append(f int) {
	cs.Lock()
	defer cs.Unlock()
	cs.items = append(cs.items, f)
}

func (cs *ConcurrentIntSlice) GetItems() []int {
	cs.RLock()
	defer cs.RUnlock()
	return cs.items
}

type ConcurrentUint16Slice struct {
	sync.RWMutex
	items []uint16
}

func NewConcurrentUint16Slice() *ConcurrentUint16Slice {
	return &ConcurrentUint16Slice{items: make([]uint16, 0)}
}

func (cs *ConcurrentUint16Slice) Append(f uint16) {
	cs.Lock()
	defer cs.Unlock()
	cs.items = append(cs.items, f)
}

func (cs *ConcurrentUint16Slice) GetItems() []uint16 {
	cs.RLock()
	defer cs.RUnlock()
	return cs.items
}

var tlsCiphersList = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                "RSA w/ RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "RSA w/ 3DES_EDE_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "RSA w/ AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "RSA w/ AES_256_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "RSA w/ AES_128_CBC_SHA256",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "RSA w/ AES_128_GCM_SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "RSA w/ AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "ECDHE ECDSA w/ RC4_128_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "ECDHE ECDSA w/ AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "ECDHE ECDSA w/ AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "ECDHE RSA w/ RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "ECDHE RSA w/ 3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "ECDHE RSA w/ AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "ECDHE RSA w/ AES_256_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "ECDHE ECDSA w/ AES_128_CBC_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "ECDHE RSA w/ AES_128_CBC_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "ECDHE RSA w/ AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "ECDHE ECDSA w/ AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "ECDHE RSA w/ AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "ECDHE ECDSA w/ AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "ECDHE RSA w/ CHACHA20_POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "ECDHE ECDSA w/ CHACHA20_POLY1305",

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See
	// https://tools.ietf.org/html/rfc7507.
	tls.TLS_FALLBACK_SCSV: "TLS_FALLBACK_SCSV",
}
