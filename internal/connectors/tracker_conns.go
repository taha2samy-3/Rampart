package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"rampart/internal/domain"
	trackerclient "rampart/internal/tracker/client"
)

// TrackerConnections keeps one gRPC connection per external tracker resource (docs/51 step 1.4). A connection is
// kept under the tracker's identity (origin, namespace, name) with a hash of what it was dialed with; when the
// spec changes the next lookup dials the new address and closes the old connection, and Close closes them all at
// shutdown. Without it the ticket sweeper dialed once per pending ticket and never closed a connection.
//
// grpc.NewClient does not connect when called (the connection is made on the first RPC and re-made when it drops),
// so dialing under the lock does not block other trackers on a slow container.
type TrackerConnections struct {
	mu     sync.Mutex
	conns  map[string]trackerConn
	closed bool
}

type trackerConn struct {
	hash string
	cli  *trackerclient.Client
}

// ErrTrackerConnectionsClosed is returned once Close has been called: the server is shutting down.
var ErrTrackerConnectionsClosed = errors.New("tracker connections are closed: the server is shutting down")

// NewTrackerConnections returns an empty connection cache.
func NewTrackerConnections() *TrackerConnections {
	return &TrackerConnections{conns: map[string]trackerConn{}}
}

// trackerIdentity is the key a stored tracker's connection is kept under.
func trackerIdentity(obj domain.StoredTrackerObject) string {
	return obj.Origin + "/" + obj.Namespace + "/" + obj.Name
}

// dialHash is what makes two dial configurations the same connection.
func dialHash(cfg trackerclient.DialConfig) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%t\x00%s\x00%x\x00%s", cfg.Target, cfg.Secure, cfg.Timeout, cfg.CACertPEM, cfg.BearerToken)))
	return hex.EncodeToString(h[:])
}

// Client returns the connection kept for key, dialing it with dial when there is none or when cfg differs from what
// the kept one was dialed with (the old one is then closed).
func (c *TrackerConnections) Client(key string, cfg trackerclient.DialConfig, dial func(trackerclient.DialConfig) (*trackerclient.Client, error)) (*trackerclient.Client, error) {
	if dial == nil {
		dial = trackerclient.Dial
	}
	hash := dialHash(cfg)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrTrackerConnectionsClosed
	}
	if c.conns == nil {
		c.conns = map[string]trackerConn{}
	}
	if kept, ok := c.conns[key]; ok {
		if kept.hash == hash {
			return kept.cli, nil
		}
		// The spec changed: a call still running on the old connection fails and is retried on the new one.
		_ = kept.cli.Close()
		delete(c.conns, key)
	}
	cli, err := dial(cfg)
	if err != nil {
		return nil, err
	}
	c.conns[key] = trackerConn{hash: hash, cli: cli}
	return cli, nil
}

// Len is how many connections are kept (for tests and metrics).
func (c *TrackerConnections) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

// Close closes every kept connection; later lookups fail with ErrTrackerConnectionsClosed.
func (c *TrackerConnections) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	var errs []error
	for k, kept := range c.conns {
		if err := kept.cli.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tracker %s: %w", k, err))
		}
		delete(c.conns, k)
	}
	return errors.Join(errs...)
}

// parseStoredTracker reads a stored tracker the way the operator checks it: a namespaced ExternalTracker may name a
// Service only in its own namespace. It is checked again here because a row stored before the rule was added would
// otherwise still be dialed.
func parseStoredTracker(obj domain.StoredTrackerObject) (domain.ExternalTrackerSpec, error) {
	if obj.Origin == "tenant" {
		return domain.ParseTenantExternalTrackerSpec(obj.Spec, obj.Namespace)
	}
	return domain.ParseExternalTrackerSpec(obj.Spec, false)
}
