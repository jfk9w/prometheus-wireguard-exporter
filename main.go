package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"

	"github.com/AlekSi/pointer"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_model/go"
)

var (
	port = flag.Int("port", 9586, "Port to listen on")
	cmd  = flag.String("cmd", "wg", "WireGuard command")
)

func main() {
	flag.Parse()
	http.Handle("/metrics", promhttp.HandlerFor(prometheus.GathererFunc(gather), promhttp.HandlerOpts{}))
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}

func gather() ([]*io_prometheus_client.MetricFamily, error) {
	out, err := exec.Command("sh", "-c", *cmd).Output()
	if err != nil {
		return nil, err
	}

	peers, err := parseDump(out)
	if err != nil {
		slog.Error("failed to parse dump", "out", string(out), "error", err)
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

// peerFields is the number of tab-separated columns in a peer line of
// `wg show all dump`: the interface name plus the eight per-peer columns.
const peerFields = 9

// parseDump parses the output of `wg show all dump` into peers. The dump prints,
// for every interface, one device line followed by its peer lines. Device lines
// carry a different number of fields (5 for WireGuard, more for AmneziaWG because
// of the junk-packet parameters), while every peer line has exactly peerFields
// columns, so non-peer lines are skipped. Peer lines that fail to parse are
// logged and skipped so that a single bad line does not break the whole scrape.
func parseDump(out []byte) ([]Peer, error) {
	reader := csv.NewReader(bytes.NewReader(out))
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1 // device and peer lines have a different number of fields

	records, err := reader.ReadAll()
	if err != nil {
		return nil, errors.Wrap(err, "decode records")
	}

	peers := make([]Peer, 0, len(records))
	for _, record := range records {
		if len(record) != peerFields {
			continue
		}

		peer, err := parsePeer(record)
		if err != nil {
			slog.Error("failed to parse peer", "record", record, "error", err)
			continue
		}

		peers = append(peers, peer)
	}

	return peers, nil
}

type Peer struct {
	Interface           string
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          string
	LatestHandshake     int64
	SentBytes           int64
	ReceivedBytes       int64
	PersistentKeepalive string
}

// parsePeer fills a Peer from one peer line of `wg show all dump`. The column
// order matches wg(8): interface, public-key, preshared-key, endpoint,
// allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive.
func parsePeer(record []string) (Peer, error) {
	latestHandshake, err := strconv.ParseInt(record[5], 10, 64)
	if err != nil {
		return Peer{}, errors.Wrap(err, "parse latest handshake")
	}

	// record[6] is transfer-rx (bytes received from the peer) and record[7] is
	// transfer-tx (bytes sent to the peer), per wg(8).
	receivedBytes, err := strconv.ParseInt(record[6], 10, 64)
	if err != nil {
		return Peer{}, errors.Wrap(err, "parse received bytes")
	}

	sentBytes, err := strconv.ParseInt(record[7], 10, 64)
	if err != nil {
		return Peer{}, errors.Wrap(err, "parse sent bytes")
	}

	return Peer{
		Interface:           record[0],
		PublicKey:           record[1],
		PresharedKey:        record[2],
		Endpoint:            record[3],
		AllowedIPs:          record[4],
		LatestHandshake:     latestHandshake,
		SentBytes:           sentBytes,
		ReceivedBytes:       receivedBytes,
		PersistentKeepalive: record[8],
	}, nil
}
