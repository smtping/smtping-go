package smtping

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBandFor(t *testing.T) {
	cases := map[string]Band{"valid": BandSafe, "alias": BandSafe, "spamtrap": BandAvoid, "catch_all": BandJudgement, "": BandJudgement}
	for status, want := range cases {
		if got := BandFor(status); got != want {
			t.Errorf("BandFor(%q) = %q, want %q", status, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	got := normalize([]string{" A@Example.com ", "a@example.com", "bad", ""}, true)
	if len(got) != 1 || got[0] != "a@example.com" {
		t.Fatalf("normalize = %v", got)
	}
}

func TestVerifyAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "sk_test" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"bad key"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"email":"a@example.com","status":"valid"}`))
	}))
	defer srv.Close()
	ctx := context.Background()

	c, err := New(WithAPIKey("sk_test"), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Verify(ctx, "a@example.com")
	if err != nil || r.Band() != BandSafe {
		t.Fatalf("Verify = %+v, %v", r, err)
	}

	bad, _ := New(WithAPIKey("nope"), WithBaseURL(srv.URL))
	if _, err := bad.Verify(ctx, "a@example.com"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("want ErrAuthentication, got %v", err)
	}
	if _, err := c.Check(ctx, "nope", "a@example.com"); !errors.Is(err, ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}
