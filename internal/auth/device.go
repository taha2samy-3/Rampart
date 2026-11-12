package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"rampart/internal/domain"
)

var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrExpiredToken         = errors.New("expired_token")
	ErrAccessDenied         = errors.New("access_denied")
	ErrInvalidGrant         = errors.New("invalid_grant")
)

// DeviceRequest tracks an RFC 8628 device authorization request.
type DeviceRequest struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scope      string
	ExpiresAt  time.Time
	Interval   int

	Approved bool
	Denied   bool
	Token    string
}

// DeviceCodeResponse is returned by POST /auth/device/code.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceTokenResponse is returned by POST /auth/device/token when approved.
type DeviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// DeviceAuthManager manages pending RFC 8628 device authorization requests (Phase 2, D8, D54).
type DeviceAuthManager struct {
	mu         sync.RWMutex
	byDevice   map[string]*DeviceRequest
	byUser     map[string]*DeviceRequest
	tokenStore TokenStore
}

func NewDeviceAuthManager(tokenStore TokenStore) *DeviceAuthManager {
	return &DeviceAuthManager{
		byDevice:   make(map[string]*DeviceRequest),
		byUser:     make(map[string]*DeviceRequest),
		tokenStore: tokenStore,
	}
}

const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ23456789"

func generateUserCode() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	chars := make([]byte, 8)
	for i := range b {
		chars[i] = userCodeAlphabet[int(b[i])%len(userCodeAlphabet)]
	}
	return fmt.Sprintf("%s-%s", string(chars[:4]), string(chars[4:]))
}

func normalizeUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) == 8 {
		return fmt.Sprintf("%s-%s", s[:4], s[4:])
	}
	return s
}

// CreateDeviceCode initiates the device flow and generates device_code and user_code.
func (m *DeviceAuthManager) CreateDeviceCode(clientID, scope, baseURL string) (*DeviceCodeResponse, error) {
	devBytes := make([]byte, 24)
	if _, err := rand.Read(devBytes); err != nil {
		return nil, fmt.Errorf("failed to generate device code: %w", err)
	}
	deviceCode := hex.EncodeToString(devBytes)
	userCode := generateUserCode()

	req := &DeviceRequest{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      scope,
		ExpiresAt:  time.Now().UTC().Add(15 * time.Minute),
		Interval:   5,
	}

	m.mu.Lock()
	m.byDevice[deviceCode] = req
	m.byUser[userCode] = req
	m.mu.Unlock()

	baseURL = strings.TrimRight(baseURL, "/")
	verifyURI := baseURL + "/auth/device"
	verifyURIComplete := fmt.Sprintf("%s?user_code=%s", verifyURI, userCode)

	return &DeviceCodeResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verifyURI,
		VerificationURIComplete: verifyURIComplete,
		ExpiresIn:               900,
		Interval:                req.Interval,
	}, nil
}

// VerifyUserCode approves a pending user code on behalf of an authenticated user.
func (m *DeviceAuthManager) VerifyUserCode(ctx context.Context, rawUserCode string, user *ContextUser) error {
	norm := normalizeUserCode(rawUserCode)

	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.byUser[norm]
	if !ok {
		return ErrInvalidGrant
	}
	if time.Now().UTC().After(req.ExpiresAt) {
		delete(m.byDevice, req.DeviceCode)
		delete(m.byUser, norm)
		return ErrExpiredToken
	}

	if user == nil || user.TenantID == domain.NilID {
		return errors.New("user has no active tenant")
	}

	subject := user.Email
	if subject == "" {
		subject = user.Subject
	}

	scopes := []string{"ingest", "read", "triage", "admin"}
	duration := 30 * 24 * time.Hour // 30 days
	rawToken, record, err := GenerateToken(user.TenantID, user.Role, subject, scopes, duration)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	if m.tokenStore != nil {
		if err := m.tokenStore.SaveToken(ctx, record); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}
	}

	req.Approved = true
	req.Token = rawToken
	return nil
}

// DenyUserCode marks the request denied.
func (m *DeviceAuthManager) DenyUserCode(rawUserCode string) error {
	norm := normalizeUserCode(rawUserCode)

	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.byUser[norm]
	if !ok {
		return ErrInvalidGrant
	}
	req.Denied = true
	return nil
}

// PollToken checks if the device code has been approved.
func (m *DeviceAuthManager) PollToken(deviceCode, clientID string) (*DeviceTokenResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.byDevice[deviceCode]
	if !ok {
		return nil, ErrInvalidGrant
	}
	if time.Now().UTC().After(req.ExpiresAt) {
		delete(m.byDevice, deviceCode)
		delete(m.byUser, req.UserCode)
		return nil, ErrExpiredToken
	}
	if req.Denied {
		delete(m.byDevice, deviceCode)
		delete(m.byUser, req.UserCode)
		return nil, ErrAccessDenied
	}
	if !req.Approved {
		return nil, ErrAuthorizationPending
	}

	// Approved! Consume the request and return token
	token := req.Token
	delete(m.byDevice, deviceCode)
	delete(m.byUser, req.UserCode)

	return &DeviceTokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   30 * 86400,
	}, nil
}
