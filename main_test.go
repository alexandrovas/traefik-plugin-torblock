package traefik_plugin_torblock_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	torblock "github.com/alexandrovas/traefik-plugin-torblock"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	})

	// Bad URLs have to return an error
	cfg := torblock.CreateConfig()
	cfg.TorExitNodeListURL = "bad"
	_, err := torblock.New(ctx, next, cfg, "torblock")
	assert.Error(err)

	// Unreachable URLs dont error but only warn
	cfg = torblock.CreateConfig()
	cfg.TorExitNodeListURL = "https://badurl.test123/test"
	_, err = torblock.New(ctx, next, cfg, "torblock")
	assert.NoError(err)

	// Too short update intervals
	cfg = torblock.CreateConfig()
	cfg.UpdateInterval = "30s"
	_, err = torblock.New(ctx, next, cfg, "torblock")
	assert.Error(err)
}

func TestRequests(t *testing.T) {
	assert := assert.New(t)

	torIPsList := `
# comment text

1.2.3.4
4.3.2.1
171.25.193.36/31
`
	// create mock server for return tor ip list
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, torIPsList)
	}))
	defer ts.Close() // Close the server when the test finishes

	cfg := torblock.CreateConfig()
	cfg.TorExitNodeListURL = ts.URL
	cfg.IPStrategy.Depth = 1
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	})

	handler, err := torblock.New(ctx, next, cfg, "torblock")
	assert.NoError(err)

	type testCase struct {
		remoteIp   string
		statusCode int
		headers    map[string]string
	}

	testCases := []testCase{
		// check blocking with by remote ip (in blocklist)
		{
			remoteIp:   "1.2.3.4",
			statusCode: http.StatusForbidden,
		},
		// check blocking with by remote ip (not in blocklist)
		{
			remoteIp:   "4.5.6.7",
			statusCode: http.StatusNoContent,
		},
		// check blocking with X-Forwarded-For (moultiple addresses, not in blacklist)
		{
			remoteIp:   "4.5.6.7",
			statusCode: http.StatusNoContent,
			headers: map[string]string{
				torblock.XForwardedForHeader: "192.168.100.1, 8.8.8.8",
			},
		},
		// check blocking with X-Forwarded-For (in blacklist)
		{
			remoteIp:   "4.5.6.7",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				torblock.XForwardedForHeader: "192.168.100.1, 1.2.3.4",
			},
		},
		// check blocking with X-Forwarded-For (in blacklist)
		{
			remoteIp:   "4.5.6.7",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				torblock.XForwardedForHeader: "1.2.3.4",
			},
		},
		// check blocking with X-Forwarded-For (not in blacklist)
		{
			remoteIp:   "1.2.3.4",
			statusCode: http.StatusNoContent,
			headers: map[string]string{
				torblock.XForwardedForHeader: "4.5.6.7",
			},
		},
		// check blocking with empty X-Forwarded-For header (use remote ip as fallback)
		{
			remoteIp:   "1.2.3.4",
			statusCode: http.StatusForbidden,
			headers: map[string]string{
				torblock.XForwardedForHeader: "",
			},
		},
		// check ip subnet blocking
		{
			remoteIp:   "171.25.193.35",
			statusCode: http.StatusNoContent,
		},
		{
			remoteIp:   "171.25.193.36",
			statusCode: http.StatusForbidden,
		},
		{
			remoteIp:   "171.25.193.37",
			statusCode: http.StatusForbidden,
		},
		{
			remoteIp:   "171.25.193.38",
			statusCode: http.StatusNoContent,
		},
	}

	// Blocked IP
	for _, tc := range testCases {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		assert.NoError(err)
		req.RemoteAddr = fmt.Sprintf("%s:%d", tc.remoteIp, 1234)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(tc.statusCode, recorder.Result().StatusCode, tc)
	}
}
