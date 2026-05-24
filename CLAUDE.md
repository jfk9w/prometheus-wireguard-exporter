# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A minimal Prometheus exporter for `wg show all dump` stats. It exists because
[mindflavor/prometheus_wireguard_exporter](https://github.com/mindflavor/prometheus_wireguard_exporter)
is hard-linked to vanilla WireGuard; here the stats command is configurable, so
it also works with AmneziaWG (`awg`). The metric names and label format
intentionally mirror mindflavor's so existing Grafana dashboards keep working.

## Commands

```sh
go build                                  # build ./prometheus-wireguard-exporter
go test ./...                             # run all tests
go test -run TestParseDumpMultipleInterfaces ./...   # run a single test
go vet ./...
go mod tidy

# run (the -cmd value is executed via `sh -c`, so pass the full command):
./prometheus-wireguard-exporter -cmd "wg show all dump"      # WireGuard
./prometheus-wireguard-exporter -cmd "awg show all dump"     # AmneziaWG
# flags: -port (default 9586), -cmd (default "wg"); metrics at /metrics
```

## Architecture

Single-file program (`main.go`, ~150 lines); `main_test.go` covers the parser.

- **Gatherer, not collectors.** `gather()` implements `prometheus.GathererFunc`
  and is wired into `promhttp.HandlerFor`. It builds `io_prometheus_client`
  `MetricFamily` protobufs by hand (using `AlekSi/pointer` for the `*T` fields)
  rather than registering `prometheus.Collector`s. The command is re-run on every
  scrape.

- **Configurable stats command.** `-cmd` is run through `sh -c`, which is the
  whole point of the project — the same code serves `wg` and `awg`.

- **Dump parsing (`parseDump`) is the subtle part.** `wg show all dump` prints,
  per interface, one *device line* followed by its *peer lines*, all tab-separated.
  Device lines have a varying field count (5 for WireGuard, ~21 for AmneziaWG due
  to the junk-packet parameters); peer lines always have exactly `peerFields` (9)
  columns. The parser reads with `csv.Reader` (`Comma='\t'`, `FieldsPerRecord=-1`)
  and keeps only 9-field rows, skipping every device line. Filtering by field count
  (rather than skipping a fixed header) is what makes multiple interfaces and
  AmneziaWG work — getting this wrong is the historical crash this code fixes.

- **rx/tx column mapping — do not swap.** Per `wg(8)`, peer column 6 is
  `transfer-rx` (→ `ReceivedBytes` → `wireguard_received_bytes_total`) and column 7
  is `transfer-tx` (→ `SentBytes` → `wireguard_sent_bytes_total`). This matches
  mindflavor. An earlier version had these reversed.

- **Emitted metrics:** `wireguard_sent_bytes_total`,
  `wireguard_received_bytes_total` (counters) and
  `wireguard_latest_handshake_seconds` (gauge), each labeled
  `interface` / `public_key` / `allowed_ips`.

- **Resilience:** a peer line that fails to parse is logged via `slog` and
  skipped, so one bad line does not fail the whole scrape.
