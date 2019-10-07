package grpc

import (
	"context"
	"fmt"

	"gopkg.in/src-d/go-log.v1"

	"github.com/lwsanty/clair-scanner/scanner"
)

type Server struct {
	Clair     string
	IP        string
	ReportAll bool
}

func NewServer(clair, ip string, reportAll bool) *Server {
	return &Server{
		Clair:     clair,
		IP:        ip,
		ReportAll: reportAll,
	}
}

func (s *Server) Scan(ctx context.Context, request *scanner.ScanRequest) (*scanner.ScanResponse, error) {
	unapproved, vulnerabilities, err := scanner.Scan(scanner.ScannerConfig{
		ImageName: request.Image,
		ClairURL:  s.Clair,
		ScannerIP: s.IP,
		ReportAll: s.ReportAll,
	})
	if err != nil {
		return nil, err
	}

	// TODO refactor
	log.Infof("unapproved: %v", unapproved)
	var res []*scanner.Vulnerability
	for _, v := range vulnerabilities {
		res = append(res, &scanner.Vulnerability{
			Status:         v.Link,
			CVEDescription: v.Description,
			CVESeverity:    v.Severity,
			PackageName:    v.FeatureName,
			PackageVersion: v.FeatureVersion,
		})
	}

	return &scanner.ScanResponse{
		Vulnerabilities: res,
	}, nil
}

// TODO
func (s *Server) Pull(ctx context.Context, request *scanner.PullRequest) (*scanner.Empty, error) {
	return nil, fmt.Errorf("not implemented")
}
