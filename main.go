package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"

	"github.com/AlekSi/pointer"
	"github.com/gocarina/gocsv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_model/go"
)

var (
	flagPort    = flag.Int("port", 9586, "Port to listen on")
	flagCommand = flag.String("cmd", "wg", "WireGuard command")
)

func main() {
	flag.Parse()
	http.Handle("/metrics", promhttp.HandlerFor(prometheus.GathererFunc(gather), promhttp.HandlerOpts{}))
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *flagPort), nil); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func gather() ([]*io_prometheus_client.MetricFamily, error) {
	out, err := exec.Command("sh", "-c", *flagCommand).Output()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(bytes.NewReader(out))
	reader.Comma = '\t'

	if _, err := reader.Read(); err != nil {
		return nil, err
	}

	var peers []Peer
	if err := gocsv.UnmarshalCSVWithoutHeaders(reader, &peers); err != nil {
		return nil, err
	}

	var (
		tx = &io_prometheus_client.MetricFamily{
			Name: pointer.To("wireguard_sent_bytes_total"),
			Help: pointer.To("Bytes sent to the peer"),
			Type: pointer.To(io_prometheus_client.MetricType_COUNTER),
		}

		rx = &io_prometheus_client.MetricFamily{
			Name: pointer.To("wireguard_received_bytes_total"),
			Help: pointer.To("Bytes received from the peer"),
			Type: pointer.To(io_prometheus_client.MetricType_COUNTER),
		}

		hs = &io_prometheus_client.MetricFamily{
			Name: pointer.To("wireguard_latest_handshake_seconds"),
			Help: pointer.To("Seconds from the last handshake"),
			Type: pointer.To(io_prometheus_client.MetricType_GAUGE),
		}
	)

	for _, peer := range peers {
		label := []*io_prometheus_client.LabelPair{
			{Name: pointer.To("interface"), Value: pointer.To(peer.Interface)},
			{Name: pointer.To("public_key"), Value: pointer.To(peer.PublicKey)},
			{Name: pointer.To("allowed_ips"), Value: pointer.To(peer.AllowedIPs)},
		}

		tx.Metric = append(tx.Metric, &io_prometheus_client.Metric{
			Label: label,
			Counter: &io_prometheus_client.Counter{
				Value: pointer.To(float64(peer.SentBytes)),
			},
		})

		rx.Metric = append(rx.Metric, &io_prometheus_client.Metric{
			Label: label,
			Counter: &io_prometheus_client.Counter{
				Value: pointer.To(float64(peer.ReceivedBytes)),
			},
		})

		hs.Metric = append(hs.Metric, &io_prometheus_client.Metric{
			Label: label,
			Gauge: &io_prometheus_client.Gauge{
				Value: pointer.To(float64(peer.LatestHandshake)),
			},
		})
	}

	return []*io_prometheus_client.MetricFamily{tx, rx, hs}, nil
}

type Peer struct {
	Interface           string `csv:"0"`
	PublicKey           string `csv:"1"`
	PresharedKey        string `csv:"2"`
	Endpoint            string `csv:"3"`
	AllowedIPs          string `csv:"4"`
	LatestHandshake     int64  `csv:"5"`
	SentBytes           int64  `csv:"6"`
	ReceivedBytes       int64  `csv:"7"`
	PersistentKeepalive int64  `csv:"8"`
}
