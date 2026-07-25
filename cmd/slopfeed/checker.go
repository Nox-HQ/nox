package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// verdict classifies a name against a registry.
type verdict string

const (
	unregistered verdict = "unregistered" // 404 confirmed twice — claimable
	registered   verdict = "registered"   // 200 — a package already owns the name
	inconclusive verdict = "inconclusive" // anything we could not resolve confidently
)

// checkResult is the outcome of checking one name.
type checkResult struct {
	name      string
	ecosystem string
	verdict   verdict
	httpCode  int
	note      string
}

// userAgent identifies the generator to registries — a good-citizen contact
// string so operators can reach us if the polling is a problem.
const userAgent = "nox-slopfeed/1.0 (+https://github.com/nox-hq/nox; supply-chain security research)"

// checker queries PyPI / npm to classify names. It is a good citizen: a
// descriptive User-Agent, a sleep between requests, exponential backoff on
// 429/5xx, and — critically — it RE-VERIFIES every 404 with a second query
// before ever asserting a name is unregistered (registries are eventually
// consistent; a single 404 is not proof). It NEVER marks a registered package
// as claimable.
type checker struct {
	client     *http.Client
	sleep      time.Duration
	maxRetries int
	// Base URLs are injectable so tests drive the checker against httptest
	// servers. In production these point at the real registries.
	pypiBase string // e.g. "https://pypi.org/pypi"
	npmBase  string // e.g. "https://registry.npmjs.org"
	requests int
}

func newChecker(client *http.Client, sleep time.Duration) *checker {
	return &checker{
		client:     client,
		sleep:      sleep,
		maxRetries: 4,
		pypiBase:   "https://pypi.org/pypi",
		npmBase:    "https://registry.npmjs.org",
	}
}

// urlFor builds the metadata URL for a name in an ecosystem.
func (c *checker) urlFor(name, ecosystem string) string {
	switch ecosystem {
	case "pypi":
		return c.pypiBase + "/" + url.PathEscape(name) + "/json"
	default: // npm
		return c.npmBase + "/" + url.PathEscape(name)
	}
}

// get performs one GET, returning the HTTP status code. It sleeps after every
// request (politeness) and backs off exponentially on 429/5xx. A code of -1
// means the request could not be completed.
func (c *checker) get(ctx context.Context, u string) (int, error) {
	backoff := time.Second
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if err != nil {
			return -1, err
		}
		req.Header.Set("User-Agent", userAgent)
		c.requests++
		resp, err := c.client.Do(req)
		if err != nil {
			select {
			case <-ctx.Done():
				return -1, ctx.Err()
			case <-time.After(backoff * time.Duration(1<<attempt)):
			}
			continue
		}
		code := resp.StatusCode
		_ = resp.Body.Close()
		switch code {
		case http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			select {
			case <-ctx.Done():
				return -1, ctx.Err()
			case <-time.After(backoff * time.Duration(1<<attempt)):
			}
			continue
		}
		c.polite(ctx)
		return code, nil
	}
	return -1, fmt.Errorf("exhausted retries for %s", u)
}

func (c *checker) polite(ctx context.Context) {
	if c.sleep <= 0 {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(c.sleep):
	}
}

// check classifies a single name. It re-verifies a 404 before trusting it.
func (c *checker) check(ctx context.Context, name, ecosystem string) checkResult {
	u := c.urlFor(name, ecosystem)
	res := checkResult{name: name, ecosystem: ecosystem, verdict: inconclusive}

	code, err := c.get(ctx, u)
	if err != nil {
		res.note = err.Error()
		return res
	}
	res.httpCode = code

	switch code {
	case http.StatusOK:
		res.verdict = registered
	case http.StatusNotFound:
		// RE-VERIFY: a squattable verdict requires two independent 404s.
		code2, err2 := c.get(ctx, u)
		if err2 != nil {
			res.verdict = inconclusive
			res.note = "404 then error on re-query: " + err2.Error()
			return res
		}
		switch code2 {
		case http.StatusNotFound:
			res.verdict = unregistered
		case http.StatusOK:
			// Eventual consistency: the name exists after all. Never accuse it.
			res.verdict = registered
			res.note = "404 then 200 on re-query (eventual consistency); treated as registered"
		default:
			res.verdict = inconclusive
			res.httpCode = code2
			res.note = fmt.Sprintf("404 then %d on re-query; inconclusive", code2)
		}
	default:
		res.verdict = inconclusive
	}
	return res
}
