package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/grpc"

	analyzerv1 "rampart/pkg/api/analyzer/v1"
)

type Server struct {
	analyzerv1.UnimplementedAnalyzerServiceServer
}

func (s *Server) HealthCheck(ctx context.Context, req *analyzerv1.HealthCheckRequest) (*analyzerv1.HealthCheckResponse, error) {
	return &analyzerv1.HealthCheckResponse{
		Status:  analyzerv1.HealthCheckResponse_SERVING,
		Message: "analyzer is healthy and ready",
	}, nil
}

func (s *Server) GetMetadata(ctx context.Context, req *analyzerv1.GetMetadataRequest) (*analyzerv1.GetMetadataResponse, error) {
	return &analyzerv1.GetMetadataResponse{
		Name:                "Sample Reference Analyzer",
		Version:             "1.0.0",
		SupportedEcosystems: []string{"npm", "maven", "pypi", "golang"},
	}, nil
}

func (s *Server) Analyze(ctx context.Context, req *analyzerv1.AnalyzeRequest) (*analyzerv1.AnalyzeResponse, error) {
	var findings []*analyzerv1.Finding

	for _, comp := range req.Components {
		// Example rule: flag lodash < 4.17.21
		if strings.Contains(strings.ToLower(comp.Name), "lodash") && strings.HasPrefix(comp.Version, "4.17.") && comp.Version < "4.17.21" {
			findings = append(findings, &analyzerv1.Finding{
				VulnerabilityId:      "CVE-2021-23337",
				Title:                "Command Injection in lodash via template",
				Severity:             "HIGH",
				CvssScore:            7.2,
				CvssVector:           "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
				Cwes:                 []int32{78, 94},
				AffectedComponentRef: comp.Ref,
				FixedVersion:         "4.17.21",
				Description:          "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via template.",
				Recommendation:       "Upgrade lodash to version 4.17.21 or later.",
				SourceAdvisoryUrl:    "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
			})
		}

		// Example rule: flag log4j-core 2.x < 2.15.0
		if strings.Contains(strings.ToLower(comp.Name), "log4j-core") && strings.HasPrefix(comp.Version, "2.") && comp.Version < "2.15.0" {
			findings = append(findings, &analyzerv1.Finding{
				VulnerabilityId:      "CVE-2021-44228",
				Title:                "Remote Code Execution in Apache Log4j (Log4Shell)",
				Severity:             "CRITICAL",
				CvssScore:            10.0,
				CvssVector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				Cwes:                 []int32{502, 400},
				AffectedComponentRef: comp.Ref,
				FixedVersion:         "2.15.0",
				Description:          "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
				Recommendation:       "Upgrade log4j-core to 2.17.1 or later.",
				SourceAdvisoryUrl:    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			})
		}
	}

	return &analyzerv1.AnalyzeResponse{
		ScanId:   req.ScanId,
		Findings: findings,
		ExecutionMetrics: map[string]string{
			"components_scanned": fmt.Sprintf("%d", len(req.Components)),
			"findings_found":     fmt.Sprintf("%d", len(findings)),
		},
	}, nil
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", port, err)
	}

	grpcServer := grpc.NewServer()
	analyzerv1.RegisterAnalyzerServiceServer(grpcServer, &Server{})

	go func() {
		log.Printf("Starting gRPC Analyzer microservice on port :%s...", port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("grpc server error: %v", err)
		}
	}()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down gRPC Analyzer...")
	grpcServer.GracefulStop()
}
