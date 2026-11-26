package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	trackerclient "rampart/internal/tracker/client"
	trackerv1 "rampart/pkg/api/tracker/v1"
)

func TestReferenceTrackerContainer(t *testing.T) {
	ctx := context.Background()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	trackerv1.RegisterTrackerServiceServer(srv, NewServer())
	go func() { _ = srv.Serve(lis) }()
	defer func() {
		srv.Stop()
		_ = lis.Close()
	}()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	cli := trackerclient.NewFromConn(conn)
	defer func() { _ = cli.Close() }()

	probe, err := trackerclient.ProbeClient(ctx, cli)
	if err != nil || !probe.Serving || probe.Provider != "reference-tracker" {
		t.Fatalf("ProbeClient failed: probe=%+v err=%v", probe, err)
	}

	target := &trackerv1.TargetContext{BindingName: "b1", Secrets: map[string]string{"token": "tok"}}
	chk, err := cli.Check(ctx, target)
	if err != nil || !chk.GetOk() {
		t.Fatalf("Check failed: chk=%+v err=%v", chk, err)
	}

	created, err := cli.CreateIssue(ctx, target, &trackerv1.IssuePayload{
		Project:          "SEC",
		Title:            "RCE",
		IdempotencyLabel: "rampart-f-123",
	})
	if err != nil || created.GetTicketId() != "SEC-1" {
		t.Fatalf("CreateIssue failed: %+v err=%v", created, err)
	}

	found, err := cli.FindIssueByLabel(ctx, target, "rampart-f-123")
	if err != nil || !found.GetFound() || found.GetTicketId() != "SEC-1" {
		t.Fatalf("FindIssueByLabel failed: %+v err=%v", found, err)
	}

	body := []byte(`{"deliveryId":"d1","ticketId":"SEC-1","actor":"alice","action":"closed","resolution":"Fixed"}`)
	mac := hmac.New(sha256.New, []byte("whsec"))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	wh, err := cli.ParseWebhook(ctx, target, map[string]string{"x-tracker-signature": sig}, body, "whsec")
	if err != nil || !wh.GetVerified() || wh.GetExternalRef() != "SEC-1" {
		t.Fatalf("ParseWebhook failed: %+v err=%v", wh, err)
	}
}
