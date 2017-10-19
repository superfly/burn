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
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"

	"github.com/montanaflynn/stats"
	"github.com/olekukonko/tablewriter"

	"github.com/abiosoft/semaphore"
)

func init() {
	RootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	RootCmd.Flags().IntP("concurrency", "c", 10, "number of concurrent requests")
	RootCmd.Flags().StringP("duration", "d", "60s", "duration for the test")
}

func Execute() {
	RootCmd.Execute()
}

const pbPrefix = "Burning..."

var timeSpent time.Duration

var (
	connectTimes      = NewConcurrentFloat64Slice()
	tlsHandshakeTimes = NewConcurrentFloat64Slice()
	ttfb              = NewConcurrentFloat64Slice()
	responseTimes     = NewConcurrentFloat64Slice()
	requestTimes      = NewConcurrentFloat64Slice()
	requestsCount     int64

	tlsCiphersUsed = []uint16{}
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

		fmt.Printf("burning on %s\n", u)

		p := mpb.New()
		pb := p.AddBar(int64(dur.Seconds()),
			mpb.PrependDecorators(
				decor.StaticName(pbPrefix, len(pbPrefix), 0),
			),
			mpb.AppendDecorators(
				// Percentage decorator with minWidth and no extra config
				decor.Percentage(5, 0),
			),
		)

		timeout := time.After(dur)
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt)

		cancel := make(chan struct{})

		ticker := time.NewTicker(time.Second)
		go func() {
			for _ = range ticker.C {
				pb.Incr(1)
			}
		}()

		sem := semaphore.New(c)

		var start time.Time
		go func() {
			start = time.Now()
			for {
				sem.Acquire()
				go func() {
					defer sem.Release()
					req := &http.Request{
						URL:    u,
						Header: make(http.Header),
					}
					ctx := httptrace.WithClientTrace(context.Background(), getClientTracer())
					start := time.Now()
					res, err := transport.RoundTrip(req.WithContext(ctx))
					atomic.AddInt64(&requestsCount, 1)
					if err != nil {
						cancel <- struct{}{}
						fmt.Printf("cancelled due to error: %s\n", err)
					}
					if res != nil {
						io.Copy(ioutil.Discard, res.Body)
					}
					responseTimes.Append(time.Since(start).Seconds())
				}()
			}
		}()

		select {
		case <-timeout:
			fmt.Println("all done")
			break
		case <-sigs:
			fmt.Println("interrupted")
			break
		case <-cancel:
			fmt.Println("cancelled!")
			break
		}

		timeSpent = time.Since(start)

		ticker.Stop()
		p.Stop()

		renderStats()
		renderMeta()

		fmt.Println("ciphers used:")
		ciphersCount := map[string]int64{}
		for _, cipher := range tlsCiphersUsed {
			ciphersCount[tlsCiphersList[cipher]] = ciphersCount[tlsCiphersList[cipher]] + 1
		}

		fmt.Printf("%+v\n", ciphersCount)

		os.Exit(0)
	},
}

func renderStats() {
	data := [][]string{}

	for name, cs := range map[string]*ConcurrentFloat64Slice{
		"Connect":               connectTimes,
		"TLS Handshake":         tlsHandshakeTimes,
		"Request fully written": requestTimes,
		"Response fully read":   responseTimes,
	} {
		d := []string{name}
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
		data = append(data, d)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Metric", "p50", "p75", "p95", "p99"})

	for _, v := range data {
		table.Append(v)
	}
	table.Render() // Send output
}

func renderMeta() {
	data := [][]string{
		[]string{"Requests Count", fmt.Sprintf("%d", requestsCount)},
		[]string{"Time spent", timeSpent.String()},
		[]string{"RPS", fmt.Sprintf("%f", float64(requestsCount)/timeSpent.Seconds())},
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetBorder(false) // Set Border to false
	table.AppendBulk(data) // Add Bulk Data
	table.Render()
}

var transport = &http.Transport{
	DisableKeepAlives:     true,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second, // I guess?
	ResponseHeaderTimeout: 60 * time.Second,

	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		DualStack: true,
	}).DialContext,

	TLSClientConfig: &tls.Config{
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	},
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
			connectTimes.Append(time.Since(connectStart).Seconds())
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(connState tls.ConnectionState, err error) {
			tlsHandshakeTimes.Append(time.Since(tlsStart).Seconds())
			tlsCiphersUsed = append(tlsCiphersUsed, connState.CipherSuite)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			requestTimes.Append(time.Since(reqStart).Seconds())
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

var tlsCiphersList = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "TLS_RSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See
	// https://tools.ietf.org/html/rfc7507.
	tls.TLS_FALLBACK_SCSV: "TLS_FALLBACK_SCSV",
}
