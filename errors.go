package smtping

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Sentinel kinds, usable with errors.Is.
var (
	ErrAuthentication      = errors.New("smtping: authentication failed")
	ErrInsufficientCredits = errors.New("smtping: insufficient credits")
	ErrRateLimit           = errors.New("smtping: rate limit exceeded")
	ErrValidation          = errors.New("smtping: invalid input")
	ErrJobFailed           = errors.New("smtping: bulk job failed")
	ErrTimeout             = errors.New("smtping: timeout")
	ErrNetwork             = errors.New("smtping: network error")
	ErrAPI                 = errors.New("smtping: API error")
)

// Error is returned by every SDK call. Use errors.Is(err, smtping.ErrInsufficientCredits)
// to branch on the kind, or errors.As to read StatusCode and Body.
type Error struct {
	Kind       error
	StatusCode int // 0 when no HTTP response was received
	Message    string
	Body       string
	Job        *BulkJob // set for ErrJobFailed
	Err        error
}

func (e *Error) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("smtping: %s (HTTP %d)", e.Message, e.StatusCode)
	}
	return "smtping: " + e.Message
}

func (e *Error) Unwrap() error { return e.Err }

func (e *Error) Is(target error) bool { return e.Kind != nil && target == e.Kind }

func validation(msg string) error { return &Error{Kind: ErrValidation, Message: msg} }

func errorFor(status int, body []byte) *Error {
	var data struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	msg := ""
	if json.Unmarshal(body, &data) == nil {
		msg = data.Error
		if msg == "" {
			msg = data.Message
		}
	}
	if msg == "" {
		msg = fmt.Sprintf("API returned HTTP %d", status)
	}
	kind := ErrAPI
	switch status {
	case 401, 403:
		kind = ErrAuthentication
	case 402:
		kind = ErrInsufficientCredits
	case 429:
		kind = ErrRateLimit
	case 400, 422:
		kind = ErrValidation
	}
	return &Error{Kind: kind, StatusCode: status, Message: msg, Body: string(body)}
}
