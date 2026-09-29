# SMTPing Email Verifier for Go

Official Go SDK for the [SMTPing](https://smtping.com) email verification API.

- Go 1.21 or later, standard library only
- `context.Context` on every call, typed errors usable with `errors.Is`
- Automatic retries on rate limits (429) and server errors (5xx)
- Bulk jobs up to 100,000 addresses, with polling built in

## Install

```bash
go get github.com/smtping/smtping-go
```

Create an API key in the [SMTPing dashboard](https://app.smtping.com). Pass it with `smtping.WithAPIKey` or set `SMTPING_API_KEY`.

## Verify one address

```go
import "github.com/smtping/smtping-go"

client, err := smtping.New() // reads SMTPING_API_KEY, or smtping.New(smtping.WithAPIKey("sk_live_..."))
if err != nil {
	log.Fatal(err)
}

r, err := client.Verify(ctx, "jane@example.com")
fmt.Println(r.Status, r.Band()) // valid safe
```

Every result has a `Band()` for simple routing:

| band | statuses | action |
| --- | --- | --- |
| `BandSafe` | valid, alias | send |
| `BandAvoid` | invalid, spamtrap, disposable, blacklisted, complainer, spambot, inbox_full | remove |
| `BandJudgement` | catch_all, unknown, role and others | your call |

## Verify a list

Small lists with parallel single calls:

```go
rows := client.VerifyMany(ctx, []string{"a@example.com", "b@example.com"}, 5)
```

Large lists as one bulk job:

```go
rows, err := client.Bulk.Run(ctx, emails, &smtping.WaitOptions{
	OnProgress: func(j *smtping.BulkJob) { fmt.Println(j.ProcessedEmails) },
})
for _, x := range rows {
	if x.Band() == smtping.BandSafe {
		// send
	}
}
```

Or step by step with `Bulk.Create`, `Bulk.Get`, `Bulk.Wait` and `Bulk.Results`.

## Threat list checks

```go
trap, err := client.Check(ctx, smtping.CheckSpamtrap, "jane@example.com")
fmt.Println(trap.Matched, trap.Source)
// also: CheckDisposable, CheckSpambot, CheckComplainer

// up to 1,000 addresses in one call
batch, err := client.CheckBatch(ctx, smtping.CheckDisposable, emails)
```

## Credits

```go
credits, err := client.Credits(ctx)
fmt.Println(credits.Remaining)
```

## Errors

```go
_, err := client.Verify(ctx, "jane@example.com")
switch {
case errors.Is(err, smtping.ErrInsufficientCredits):
	// top up
case err != nil:
	var e *smtping.Error
	if errors.As(err, &e) {
		fmt.Println(e.StatusCode, e.Message)
	}
}
```

Kinds: `ErrAuthentication`, `ErrInsufficientCredits`, `ErrRateLimit`, `ErrValidation`, `ErrJobFailed`, `ErrTimeout`, `ErrNetwork`, `ErrAPI`.

## Options

| option | default | |
| --- | --- | --- |
| `WithAPIKey` | `SMTPING_API_KEY` | required |
| `WithBaseURL` | `https://api.smtping.com/api/v1` | |
| `WithTimeout` | 60 seconds | per request |
| `WithMaxRetries` | `3` | network errors, 429, 5xx |
| `WithHTTPClient` | `http.DefaultClient` | |

## Links

- [API documentation](https://smtping.com/docs)
- [Pricing](https://smtping.com/pricing)
- Support: support@smtping.com

MIT License
