// +build integration

package main

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lwsanty/clair-scanner/scanner"
)

var (
	ip = flag.String("ip", "localhost", "scanner ip")
)

func TestMain(m *testing.M) {
	flag.Parse()
	result := m.Run()
	os.Exit(result)
}

func TestDebian(t *testing.T) {
	initializeLogger("")
	unapproved, err := scanner.Scan(scanner.ScannerConfig{
		"debian:jessie",
		scanner.vulnerabilitiesWhitelist{},
		"http://127.0.0.1:6060",
		*ip,
		"",
		"Unknown",
		true,
		false,
	})
	require.NoError(t, err)
	if len(unapproved) == 0 {
		t.Errorf("No vulnerabilities, expecting some")
	}
}
