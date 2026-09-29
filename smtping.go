// Package smtping is the official Go SDK for the SMTPing email verification API.
package smtping

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultBaseURL = "https://api.smtping.com/api/v1"
	BulkMax        = 100000
	BatchMax       = 1000
	modulePath     = "github.com/smtping/smtping-go"
)

// Band is a simple routing for a verification result.
type Band string

const (
	BandSafe      Band = "safe"      // valid, alias: send
	BandAvoid     Band = "avoid"     // invalid, spamtrap, disposable, blacklisted, complainer, spambot, inbox_full: remove
	BandJudgement Band = "judgement" // catch_all, unknown, role and others: your call
)

// Check is a threat list available to Client.Check and Client.CheckBatch.
type Check string

const (
	CheckSpamtrap   Check = "spamtrap"
	CheckDisposable Check = "disposable"
	CheckSpambot    Check = "spambot"
	CheckComplainer Check = "complainer"
)

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// IsEmail is the basic syntax check the SDK applies before bulk jobs and batch checks.
func IsEmail(v string) bool { return emailRe.MatchString(strings.TrimSpace(v)) }

// BandFor returns the routing band for a verification status.
func BandFor(status string) Band {
	switch status {
	case "valid", "alias":
		return BandSafe
	case "invalid", "spamtrap", "disposable", "blacklisted", "complainer", "spambot", "inbox_full":
		return BandAvoid
	}
	return BandJudgement
}

// Version returns the module version, as resolved by the Go toolchain.
func Version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Path == modulePath && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			return strings.TrimPrefix(bi.Main.Version, "v")
		}
		for _, d := range bi.Deps {
			if d.Path == modulePath {
				return strings.TrimPrefix(d.Version, "v")
			}
		}
	}
	return "dev"
}

type VerifyResult struct {
	Email             string `json:"email"`
	Status            string `json:"status"`
	StatusDescription string `json:"statusDescription,omitempty"`
	IsDisposable      *bool  `json:"isDisposable,omitempty"`
	IsFreeDomain      *bool  `json:"isFreeDomain,omitempty"`
	IsRoleBasedDomain *bool  `json:"isRoleBasedDomain,omitempty"`
	IsTypos           *bool  `json:"isTypos,omitempty"`
}

// Band returns Safe, Avoid or Judgement, derived from Status.
func (r VerifyResult) Band() Band { return BandFor(r.Status) }

type CheckResult struct {
	Email            string `json:"email"`
	Check            string `json:"check"`
	Matched          bool   `json:"matched"`
	Source           string `json:"source,omitempty"`
	CreditsCharged   int64  `json:"creditsCharged"`
	RemainingCredits int64  `json:"remainingCredits"`
}

type CheckBatchItem struct {
	Email   string `json:"email"`
	Matched bool   `json:"matched"`
	Source  string `json:"source,omitempty"`
}

type CheckBatchResult struct {
	Check            string           `json:"check"`
	Checked          int              `json:"checked"`
	Matched          int              `json:"matched"`
	CreditsCharged   int64            `json:"creditsCharged"`
	RemainingCredits int64            `json:"remainingCredits"`
	Results          []CheckBatchItem `json:"results"`
}

type Credits struct {
	Remaining int64  `json:"remaining"`
	Plan      string `json:"plan,omitempty"`
}

// Client calls the SMTPing API. Create it with New; it is safe for concurrent use.
type Client struct {
	apiKey     string
	BaseURL    string
	Timeout    time.Duration // per request
	MaxRetries int           // network errors, 429, 5xx
	UserAgent  string
	HTTPClient *http.Client
	Bulk       *BulkService
}

type Option func(*Client)

func WithAPIKey(key string) Option           { return func(c *Client) { c.apiKey = strings.TrimSpace(key) } }
func WithBaseURL(url string) Option          { return func(c *Client) { c.BaseURL = strings.TrimSpace(url) } }
func WithTimeout(d time.Duration) Option     { return func(c *Client) { c.Timeout = d } }
func WithMaxRetries(n int) Option            { return func(c *Client) { c.MaxRetries = n } }
func WithUserAgent(ua string) Option         { return func(c *Client) { c.UserAgent = ua } }
func WithHTTPClient(h *http.Client) Option   { return func(c *Client) { c.HTTPClient = h } }

// New creates a client. The API key defaults to the SMTPING_API_KEY environment variable.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		apiKey:     strings.TrimSpace(os.Getenv("SMTPING_API_KEY")),
		BaseURL:    DefaultBaseURL,
		Timeout:    60 * time.Second,
		MaxRetries: 3,
		UserAgent:  "smtping-go/" + Version(),
		HTTPClient: http.DefaultClient,
	}
	if u := strings.TrimSpace(os.Getenv("SMTPING_BASE_URL")); u != "" {
		c.BaseURL = u
	}
	for _, o := range opts {
		o(c)
	}
	if c.apiKey == "" {
		return nil, &Error{Kind: ErrAuthentication, Message: "missing API key: pass smtping.WithAPIKey or set SMTPING_API_KEY"}
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultBaseURL
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}
	c.Bulk = &BulkService{c: c}
	return c, nil
}

// Verify checks one address.
func (c *Client) Verify(ctx context.Context, email string) (*VerifyResult, error) {
	e := strings.TrimSpace(email)
	if e == "" {
		return nil, validation("email is required")
	}
	var r VerifyResult
	if err := c.Request(ctx, http.MethodPost, "/verify/single", map[string]string{"email": e}, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// VerifyMany verifies a small list with parallel single calls. Failed addresses come back with status "error".
func (c *Client) VerifyMany(ctx context.Context, emails []string, concurrency int) []VerifyResult {
	list := normalize(emails, false)
	out := make([]VerifyResult, len(list))
	if concurrency < 1 {
		concurrency = 5
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, e := range list {
		wg.Add(1)
		go func(i int, e string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r, err := c.Verify(ctx, e)
			if err != nil {
				out[i] = VerifyResult{Email: e, Status: "error", StatusDescription: err.Error()}
				return
			}
			out[i] = *r
		}(i, e)
	}
	wg.Wait()
	return out
}

// Check looks one address up in a threat list.
func (c *Client) Check(ctx context.Context, check Check, email string) (*CheckResult, error) {
	t, err := validCheck(check)
	if err != nil {
		return nil, err
	}
	e := strings.TrimSpace(email)
	var r CheckResult
	if err := c.Request(ctx, http.MethodPost, "/checks/"+string(t), map[string]string{"email": e}, &r); err != nil {
		return nil, err
	}
	if r.Email == "" {
		r.Email = e
	}
	if r.Check == "" {
		r.Check = string(t)
	}
	return &r, nil
}

// CheckBatch looks up to 1,000 addresses up in a threat list in one call.
func (c *Client) CheckBatch(ctx context.Context, check Check, emails []string) (*CheckBatchResult, error) {
	t, err := validCheck(check)
	if err != nil {
		return nil, err
	}
	list := normalize(emails, true)
	if len(list) == 0 {
		return nil, validation("no valid email address in the list")
	}
	if len(list) > BatchMax {
		return nil, validation(fmt.Sprintf("a batch check accepts up to %d addresses, use a job above that", BatchMax))
	}
	var r CheckBatchResult
	if err := c.Request(ctx, http.MethodPost, "/checks/"+string(t)+"/batch", map[string][]string{"emails": list}, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Credits returns the remaining credit balance.
func (c *Client) Credits(ctx context.Context) (*Credits, error) {
	var r Credits
	if err := c.Request(ctx, http.MethodGet, "/credits", nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Request is a low-level call to any endpoint. It retries network errors, 429 and 5xx,
// and decodes a JSON response into out when out is not nil.
func (c *Client) Request(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = b
	}
	for attempt := 0; ; attempt++ {
		status, data, header, err := c.do(ctx, method, path, payload)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt < c.MaxRetries {
				if serr := sleepCtx(ctx, backoff(attempt+1)); serr != nil {
					return serr
				}
				continue
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return &Error{Kind: ErrTimeout, Message: "request timed out after " + c.Timeout.String(), Err: err}
			}
			return &Error{Kind: ErrNetwork, Message: "network error: " + err.Error(), Err: err}
		}
		if status >= 200 && status < 300 {
			if out == nil || len(bytes.TrimSpace(data)) == 0 {
				return nil
			}
			if err := json.Unmarshal(data, out); err != nil {
				return &Error{Kind: ErrAPI, StatusCode: status, Message: "invalid JSON response", Body: string(data), Err: err}
			}
			return nil
		}
		if (status == http.StatusTooManyRequests || status >= 500) && attempt < c.MaxRetries {
			wait := backoff(attempt + 1)
			if s, perr := strconv.Atoi(strings.TrimSpace(header.Get("Retry-After"))); perr == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			if serr := sleepCtx(ctx, wait); serr != nil {
				return serr
			}
			continue
		}
		return errorFor(status, data)
	}
}

func (c *Client) do(ctx context.Context, method, path string, payload []byte) (int, []byte, http.Header, error) {
	rctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(rctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	return res.StatusCode, data, res.Header, nil
}

func normalize(emails []string, validOnly bool) []string {
	seen := make(map[string]bool, len(emails))
	out := make([]string, 0, len(emails))
	for _, e := range emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || seen[e] || (validOnly && !IsEmail(e)) {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

func validCheck(c Check) (Check, error) {
	t := Check(strings.ToLower(strings.TrimSpace(string(c))))
	switch t {
	case CheckSpamtrap, CheckDisposable, CheckSpambot, CheckComplainer:
		return t, nil
	}
	return "", validation(fmt.Sprintf("unknown check %q: use spamtrap, disposable, spambot or complainer", string(c)))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func backoff(attempt int) time.Duration {
	ms := math.Min(1000*math.Pow(2, float64(attempt-1)), 15000) + float64(rand.Intn(250))
	return time.Duration(ms) * time.Millisecond
}
