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
	flags := rootCmd.Flags()

	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	flags.IntP("concurrency", "c", 10, "number of concurrent requests")
	flags.StringP("duration", "d", "60s", "duration for the test")
	flags.StringP("timeout", "t", "2s", "connection timeout")

	flags.BoolP("insecure-skip-verify", "k", true, "allow insecure TLS certificates (self-signed, wrong hostname, etc. default: true)")
	flags.Bool("disable-keepalives", false, "disable reusing connections via keepalives (default: false)")
	flags.Bool("resume-tls", false, "allow resuming TLS (default: false)")

	flags.StringArrayP("header", "H", []string{}, "headers to send")

}

// Execute ..
func Execute() {
	rootCmd.Execute()
}

var timeSpent time.Duration

var (
	connectTimes      = newConcurrentFloat64Slice()
	tlsHandshakeTimes = newConcurrentFloat64Slice()
	ttfb              = newConcurrentFloat64Slice()
	responseTimes     = newConcurrentFloat64Slice()
	requestTimes      = newConcurrentFloat64Slice()
	headerTimes       = newConcurrentFloat64Slice()
	requestsCount     int64

	tlsCiphersUsed = newConcurrentUint16Slice()
	tlsReusedCount int64

	errors   = newConcurrentErrorSlice()
	statuses = newConcurrentIntSlice()
)

var rootCmd = &cobra.Command{
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
						go responseTimes.append(time.Since(reqStart).Seconds())
					}()

					ctx := httptrace.WithClientTrace(context.Background(), getClientTracer())
					reqStart = time.Now()
					res, err := transport.RoundTrip(req.WithContext(ctx))
					go atomic.AddInt64(&requestsCount, 1)
					if err != nil {
						go errors.append(err)
						return
					}
					go statuses.append(res.StatusCode)

					if res.Body != nil {
						if _, err := io.Copy(ioutil.Discard, res.Body); err != nil {
							go errors.append(err)
						}
						if err := res.Body.Close(); err != nil {
							go errors.append(err)
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

		if len(tlsCiphersUsed.getItems()) > 0 {
			fmt.Println(aurora.Blue("\nCiphers:"))
			ciphersCount := map[string]int64{}
			for _, cipher := range tlsCiphersUsed.getItems() {
				ciphersCount[tlsCiphersList[cipher]] = ciphersCount[tlsCiphersList[cipher]] + 1
			}
			for n, count := range ciphersCount {
				fmt.Printf("%s => %d\n", n, count)
			}
		}

		fmt.Println(aurora.Red("\nStatus code:"))
		statusCount := map[int]int64{}
		for _, s := range statuses.getItems() {
			statusCount[s] = statusCount[s] + 1
		}

		for n, count := range statusCount {
			fmt.Printf("%d => %d\n", n, count)
		}

		fmt.Println(aurora.Red("\nErrors:"))
		fmt.Printf("%d errors.\n", len(errors.getItems()))
		// if len(errors.getItems()) > 0 {
		errorsCount := map[string]int64{}
		for _, err := range errors.getItems() {
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

type statsFn func(input stats.Float64Data) (min float64, err error)

func renderStats() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoFormatHeaders(false)
	table.SetHeader([]string{"Metric", "p50", "p95", "p99", "Min", "Mean", "Max", "Std. Dev"})
	table.SetHeaderColor(nil, nil, nil, nil, nil, nil, nil, tablewriter.Color(tablewriter.FgHiBlackColor))
	table.SetColumnColor(nil, nil, nil, nil, nil, nil, nil, tablewriter.Color(tablewriter.FgHiBlackColor))

	m := map[int]string{
		0: "Connect",
		1: "TLS Handshake",
		2: "Headers written",
		3: "Request written",
		4: "TTFB",
		5: "Response read",
	}

	var keys []int
	for k := range m {
		keys = append(keys, k)
	}

	csm := map[int]*concurrentFloat64Slice{
		0: connectTimes,
		1: tlsHandshakeTimes,
		2: headerTimes,
		3: requestTimes,
		4: ttfb,
		5: responseTimes,
	}

	sort.Ints(keys)

	for _, k := range keys {
		name := m[k]
		cs := csm[k]
		row := []string{name}
		if len(cs.getItems()) == 0 {
			continue
		}

		for _, p := range []int{50, 95, 99} {
			pf, err := stats.Percentile(cs.getItems(), float64(p))
			if err != nil {
				panic(err)
			}
			ps := fmt.Sprintf("%f", pf)
			pd, err := time.ParseDuration(ps + "s")
			if err != nil {
				panic(err)
			}
			row = append(row, pd.String())
		}

		for _, f := range []statsFn{stats.Min, stats.Mean, stats.Max, stats.StandardDeviation} {
			stat, err := f(cs.getItems())
			if err != nil {
				panic(err)
			}
			secs, err := time.ParseDuration(fmt.Sprintf("%fs", stat))
			if err != nil {
				panic(err)
			}
			row = append(row, secs.String())
		}

		table.Append(row)
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

	t, err := cmd.Flags().GetString("timeout")
	if err != nil {
		panic(err)
	}
	timeout, err := time.ParseDuration(t)
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
			Timeout:   timeout,
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
			go connectTimes.append(time.Since(connectStart).Seconds())
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(connState tls.ConnectionState, err error) {
			go tlsHandshakeTimes.append(time.Since(tlsStart).Seconds())
			go tlsCiphersUsed.append(connState.CipherSuite)
			if connState.DidResume {
				go atomic.AddInt64(&tlsReusedCount, 1)
			}
		},
		WroteHeaders: func() {
			go headerTimes.append(time.Since(reqStart).Seconds())
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			go requestTimes.append(time.Since(reqStart).Seconds())
		},
		GotFirstResponseByte: func() {
			go ttfb.append(time.Since(reqStart).Seconds())
		},
	}
}

type concurrentFloat64Slice struct {
	sync.RWMutex
	items []float64
}

func newConcurrentFloat64Slice() *concurrentFloat64Slice {
	return &concurrentFloat64Slice{items: make([]float64, 0)}
}

func (cs *concurrentFloat64Slice) append(f float64) {
	cs.Lock()
	defer cs.Unlock()

	cs.items = append(cs.items, f)
}

func (cs *concurrentFloat64Slice) getItems() []float64 {
	cs.RLock()
	defer cs.RUnlock()
	return cs.items
}

type concurrentErrorSlice struct {
	sync.RWMutex
	items []error
}

func newConcurrentErrorSlice() *concurrentErrorSlice {
	return &concurrentErrorSlice{items: make([]error, 0)}
}

func (cs *concurrentErrorSlice) append(f error) {
	cs.Lock()
	defer cs.Unlock()

	cs.items = append(cs.items, f)
}

func (cs *concurrentErrorSlice) getItems() []error {
	cs.RLock()
	defer cs.RUnlock()
	return cs.items
}

type concurrentIntSlice struct {
	sync.RWMutex
	items []int
}

func newConcurrentIntSlice() *concurrentIntSlice {
	return &concurrentIntSlice{items: make([]int, 0)}
}

func (cs *concurrentIntSlice) append(f int) {
	cs.Lock()
	defer cs.Unlock()
	cs.items = append(cs.items, f)
}

func (cs *concurrentIntSlice) getItems() []int {
	cs.RLock()
	defer cs.RUnlock()
	return cs.items
}

type concurrentUint16Slice struct {
	sync.RWMutex
	items []uint16
}

func newConcurrentUint16Slice() *concurrentUint16Slice {
	return &concurrentUint16Slice{items: make([]uint16, 0)}
}

func (cs *concurrentUint16Slice) append(f uint16) {
	cs.Lock()
	defer cs.Unlock()
	cs.items = append(cs.items, f)
}

func (cs *concurrentUint16Slice) getItems() []uint16 {
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
