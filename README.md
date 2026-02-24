# Prometheus WireGuard Exporter

This is a very basic Prometheus exporter for `wg show all dump` stats.

Metrics format follows [prometheus_wireguard_exporter](https://github.com/MindFlavor/prometheus_wireguard_exporter) without
any additional options like friendly names or handshake delay (at least for now).

The only reason this project exists is that I wanted to export AmneziaWG stats and didn't want to update my Grafana dashboards.
Since MindFlavor's exporter is hard-linked to vanilla WireGuard (or at least I think so), I developed this tool which allows to
specify the command for collecting stats.
