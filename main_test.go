package main

import (
	"reflect"
	"strings"
	"testing"
)

// All public keys, endpoints and addresses below are anonymized: the keys are
// made-up base64-looking strings, endpoints use the documentation ranges from
// RFC 5737 (198.51.100.0/24, 203.0.113.0/24) and allowed-ips use RFC 1918
// private ranges.
const (
	wg0PrivKey  = "PRIV0wg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0="
	wg0PubKey   = "PUB00wg0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0="
	awg0PrivKey = "PRIVawg0CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCa="
	awg0PubKey  = "PUB0awg0DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDa="

	peerAPubKey = "PEERaEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEa="
	peerBPubKey = "PEERbFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFb="
	peerCPubKey = "PEERcGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGc="
)

// line joins fields with tabs, the field separator used by `wg show all dump`.
func line(fields ...string) string {
	return strings.Join(fields, "\t")
}

// dump joins lines into a single dump payload with a trailing newline, matching
// the output of `wg show all dump`.
func dump(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func TestParseDumpMultipleInterfaces(t *testing.T) {
	out := dump(
		// wg0: a standard WireGuard device line (5 columns) — must be skipped.
		line("wg0", wg0PrivKey, wg0PubKey, "51820", "off"),
		// wg0 peers.
		line("wg0", peerAPubKey, "(none)", "203.0.113.10:51820", "10.0.0.2/32", "1700000000", "100", "200", "25"),
		line("wg0", peerBPubKey, "(none)", "(none)", "10.0.0.3/32", "0", "0", "0", "off"),
		// awg0: an AmneziaWG device line (21 columns with junk-packet params) —
		// must be skipped. This is the line that used to crash the exporter.
		line("awg0", awg0PrivKey, awg0PubKey, "2053", "8", "50", "1000", "79", "134", "47", "19",
			"1-2", "3-4", "5-6", "7-8", "<b 0x01><r 2>", "<r 1>", "<t>", "<rc 2>", "<r 3>", "off"),
		// awg0 peer with a comma-separated allowed-ips list.
		line("awg0", peerCPubKey, "(none)", "198.51.100.7:2053", "10.1.0.0/24,10.1.1.5/32", "1700000500", "300", "400", "off"),
	)

	got, err := parseDump(out)
	if err != nil {
		t.Fatalf("parseDump returned error: %v", err)
	}

	want := []Peer{
		{
			Interface:           "wg0",
			PublicKey:           peerAPubKey,
			PresharedKey:        "(none)",
			Endpoint:            "203.0.113.10:51820",
			AllowedIPs:          "10.0.0.2/32",
			LatestHandshake:     1700000000,
			ReceivedBytes:       100, // transfer-rx, column 6
			SentBytes:           200, // transfer-tx, column 7
			PersistentKeepalive: "25",
		},
		{
			Interface:           "wg0",
			PublicKey:           peerBPubKey,
			PresharedKey:        "(none)",
			Endpoint:            "(none)",
			AllowedIPs:          "10.0.0.3/32",
			LatestHandshake:     0,
			ReceivedBytes:       0,
			SentBytes:           0,
			PersistentKeepalive: "off",
		},
		{
			Interface:           "awg0",
			PublicKey:           peerCPubKey,
			PresharedKey:        "(none)",
			Endpoint:            "198.51.100.7:2053",
			AllowedIPs:          "10.1.0.0/24,10.1.1.5/32",
			LatestHandshake:     1700000500,
			ReceivedBytes:       300,
			SentBytes:           400,
			PersistentKeepalive: "off",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDump mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// TestParseDumpSkipsDeviceLines guards against device lines (5-field WireGuard
// and many-field AmneziaWG) leaking into the parsed peers.
func TestParseDumpSkipsDeviceLines(t *testing.T) {
	out := dump(
		line("wg0", wg0PrivKey, wg0PubKey, "51820", "off"),
		line("awg0", awg0PrivKey, awg0PubKey, "2053", "8", "50", "1000", "79", "134", "47", "19",
			"1-2", "3-4", "5-6", "7-8", "<b 0x01>", "<r 1>", "<t>", "<rc 2>", "<r 3>", "off"),
	)

	got, err := parseDump(out)
	if err != nil {
		t.Fatalf("parseDump returned error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no peers from device-only dump, got %d: %+v", len(got), got)
	}
}

// TestParseDumpSentReceivedNotSwapped is a regression test for the rx/tx mapping:
// column 6 is transfer-rx (received) and column 7 is transfer-tx (sent), matching
// wg(8) and mindflavor/prometheus_wireguard_exporter.
func TestParseDumpSentReceivedNotSwapped(t *testing.T) {
	out := dump(
		line("wg0", peerAPubKey, "(none)", "203.0.113.10:51820", "10.0.0.2/32", "1700000000", "111", "222", "25"),
	)

	got, err := parseDump(out)
	if err != nil {
		t.Fatalf("parseDump returned error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(got))
	}
	if got[0].ReceivedBytes != 111 {
		t.Errorf("ReceivedBytes = %d, want 111 (transfer-rx, column 6)", got[0].ReceivedBytes)
	}
	if got[0].SentBytes != 222 {
		t.Errorf("SentBytes = %d, want 222 (transfer-tx, column 7)", got[0].SentBytes)
	}
}

// TestParseDumpSkipsMalformedPeer ensures a peer line with a non-numeric counter
// is skipped instead of failing the whole scrape, while valid peers still parse.
func TestParseDumpSkipsMalformedPeer(t *testing.T) {
	out := dump(
		line("wg0", peerAPubKey, "(none)", "203.0.113.10:51820", "10.0.0.2/32", "1700000000", "100", "200", "25"),
		line("wg0", peerBPubKey, "(none)", "(none)", "10.0.0.3/32", "1700000000", "not-a-number", "0", "off"),
	)

	got, err := parseDump(out)
	if err != nil {
		t.Fatalf("parseDump returned error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 valid peer, got %d: %+v", len(got), got)
	}
	if got[0].PublicKey != peerAPubKey {
		t.Errorf("unexpected peer parsed: %+v", got[0])
	}
}

func TestParseDumpEmpty(t *testing.T) {
	got, err := parseDump(nil)
	if err != nil {
		t.Fatalf("parseDump returned error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no peers, got %d", len(got))
	}
}
