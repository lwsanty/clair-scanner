package grpc

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"gopkg.in/src-d/go-log.v1"

	"github.com/lwsanty/clair-scanner/scanner"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

const (
	port    = ":8888"
	address = "localhost" + port
)

// TODO run Clair
// docker run -p 5432:5432 -d --name db arminc/clair-db:2017-09-18
// sleep 5
// docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan:v2.0.6
// TODO refactor
func TestGRPC(t *testing.T) {
	lis, err := net.Listen("tcp", port)
	require.NoError(t, err)

	s := grpc.NewServer()
	scanner.RegisterScannerServer(s, NewServer("http://127.0.0.1:6060", "172.17.0.1", true))

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Errorf(err, "failed to serve")
		}
		time.Sleep(2 * time.Second)
	}()

	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Errorf(err, "did not connect: %v")
	}
	defer conn.Close()
	c := scanner.NewScannerClient(conn)

	resp, err := c.Scan(context.Background(), &scanner.ScanRequest{Image: "bblfsh/bblfshd:v2.14.0-drivers-2019-10-04T14_11"})
	require.NoError(t, err)

	for _, v := range resp.Vulnerabilities {
		fmt.Println(v.Status, v.PackageName, v.PackageVersion, v.CVESeverity, v.CVEDescription)
	}
}
