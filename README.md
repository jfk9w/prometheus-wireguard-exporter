# Prometheus WireGuard Exporter

This is a very basic Prometheus exporter for `wg show all dump` stats.

Metrics format follows [prometheus_wireguard_exporter](https://github.com/MindFlavor/prometheus_wireguard_exporter) without
any additional options like friendly names or handshake delay (at least for now).

The only reason this project exists is that I wanted to export AmneziaWG stats and didn't want to update my Grafana dashboards.
Since MindFlavor's exporter is hard-linked to vanilla WireGuard (or at least I think so), I developed this tool which allows to
specify the command for collecting stats.

## Build

```sh
go build
```

## Usage

```sh
# vanilla WireGuard
prometheus-wireguard-exporter -cmd "wg show all dump"

# AmneziaWG
prometheus-wireguard-exporter -cmd "awg show all dump"
```

Flags:

| Flag    | Default | Description                                                                       |
|---------|---------|----------------------------------------------------------------------------------|
| `-cmd`  | `wg`    | Command producing a `wg ... dump` payload. Executed via `sh -c` on every scrape. |
| `-port` | `9586`  | Port the `/metrics` endpoint listens on.                                         |

The `-cmd` value is run through `sh -c`, so pass the full command (e.g.
`"wg show all dump"`). It must emit the tab-separated `wg show all dump` format;
the exporter parses both vanilla WireGuard and AmneziaWG dumps (including
multiple interfaces). The dump command typically requires root or `CAP_NET_ADMIN`.

## Metrics

Exposed at `http://<host>:<port>/metrics`, each labeled by `interface`,
`public_key` and `allowed_ips`:

- `wireguard_sent_bytes_total` — bytes sent to the peer (counter)
- `wireguard_received_bytes_total` — bytes received from the peer (counter)
- `wireguard_latest_handshake_seconds` — UNIX time of the last handshake (gauge)

## Running with systemd

`/etc/systemd/system/prometheus-wireguard-exporter.service`:

```ini
[Unit]
Description=Prometheus WireGuard Exporter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/prometheus-wireguard-exporter -cmd "awg show all dump" -port 9586
Restart=on-failure
# `awg`/`wg show` needs network admin privileges:
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now prometheus-wireguard-exporter
```
