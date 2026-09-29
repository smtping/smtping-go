package smtping

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type BulkJob struct {
	JobID           string `json:"jobId"`
	Status          string `json:"status"` // Queued, Processing, Succeeded, Failed or Cancelled
	TotalEmails     int    `json:"totalEmails"`
	ProcessedEmails int    `json:"processedEmails"`
	ErrorMessage    string `json:"errorMessage,omitempty"`
}

type WaitOptions struct {
	Timeout    time.Duration // maximum wait, default 30 minutes
	Interval   time.Duration // first poll interval, grows to 30 seconds, default 5 seconds
	OnProgress func(*BulkJob)
}

// BulkService submits lists, polls jobs and fetches results.
type BulkService struct{ c *Client }

// Create submits up to 100,000 addresses. Duplicates and malformed addresses are removed first.
func (b *BulkService) Create(ctx context.Context, emails []string) (*BulkJob, error) {
	list := normalize(emails, true)
	if len(list) == 0 {
		return nil, validation("no valid email address in the list")
	}
	if len(list) > BulkMax {
		return nil, validation(fmt.Sprintf("a bulk job accepts up to %d addresses", BulkMax))
	}
	var job BulkJob
	if err := b.c.Request(ctx, http.MethodPost, "/verify/bulk", map[string][]string{"emails": list}, &job); err != nil {
		return nil, err
	}
	if job.TotalEmails == 0 {
		job.TotalEmails = len(list)
	}
	return &job, nil
}

func (b *BulkService) Get(ctx context.Context, jobID string) (*BulkJob, error) {
	var job BulkJob
	if err := b.c.Request(ctx, http.MethodGet, "/verify/bulk/"+url.PathEscape(jobID), nil, &job); err != nil {
		return nil, err
	}
	if job.JobID == "" {
		job.JobID = jobID
	}
	return &job, nil
}

func (b *BulkService) Results(ctx context.Context, jobID string) ([]VerifyResult, error) {
	var raw json.RawMessage
	if err := b.c.Request(ctx, http.MethodGet, "/verify/bulk/"+url.PathEscape(jobID)+"/result", nil, &raw); err != nil {
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return []VerifyResult{}, nil
	}
	if raw[0] == '{' {
		var wrap struct {
			Results []VerifyResult `json:"results"`
		}
		if err := json.Unmarshal(raw, &wrap); err != nil {
			return nil, err
		}
		return wrap.Results, nil
	}
	var list []VerifyResult
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// Wait polls until the job succeeds, then returns its results.
func (b *BulkService) Wait(ctx context.Context, jobID string, opts *WaitOptions) ([]VerifyResult, error) {
	timeout, delay := 30*time.Minute, 5*time.Second
	var progress func(*BulkJob)
	if opts != nil {
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
		if opts.Interval > 0 {
			delay = opts.Interval
		}
		progress = opts.OnProgress
	}
	deadline := time.Now().Add(timeout)
	for {
		job, err := b.Get(ctx, jobID)
		if err != nil {
			return nil, err
		}
		if progress != nil {
			progress(job)
		}
		switch {
		case strings.EqualFold(job.Status, "Succeeded"):
			return b.Results(ctx, jobID)
		case strings.EqualFold(job.Status, "Failed"), strings.EqualFold(job.Status, "Cancelled"):
			msg := fmt.Sprintf("job %s %s", jobID, strings.ToLower(job.Status))
			if job.ErrorMessage != "" {
				msg += ": " + job.ErrorMessage
			}
			return nil, &Error{Kind: ErrJobFailed, Message: msg, Job: job}
		}
		if time.Now().Add(delay).After(deadline) {
			return nil, &Error{Kind: ErrTimeout, Message: fmt.Sprintf("job %s still running after %s", jobID, timeout)}
		}
		if err := sleepCtx(ctx, delay); err != nil {
			return nil, err
		}
		delay = time.Duration(float64(delay) * 1.5)
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}

// Run creates a job and waits for its results in one call.
func (b *BulkService) Run(ctx context.Context, emails []string, opts *WaitOptions) ([]VerifyResult, error) {
	job, err := b.Create(ctx, emails)
	if err != nil {
		return nil, err
	}
	return b.Wait(ctx, job.JobID, opts)
}
