package protocol

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRelatedOrigins(t *testing.T) {
	testCases := []struct {
		name     string
		have     []string
		expected []string
		err      string
	}{
		{
			name:     "ShouldAcceptASingleOrigin",
			have:     []string{"https://example.com"},
			expected: []string{"https://example.com"},
		},
		{
			name:     "ShouldAcceptOriginsSharingALabel",
			have:     []string{"https://example.com", "https://example.com.au", "https://example.de"},
			expected: []string{"https://example.com", "https://example.com.au", "https://example.de"},
		},
		{
			name:     "ShouldPreserveANonDefaultPort",
			have:     []string{"https://example.com:8443"},
			expected: []string{"https://example.com:8443"},
		},
		{
			name:     "ShouldNormalizeAwayAPath",
			have:     []string{"https://example.com/"},
			expected: []string{"https://example.com"},
		},
		{
			name:     "ShouldNormalizeAwayAQueryAndFragment",
			have:     []string{"https://example.com/x?y=z"},
			expected: []string{"https://example.com"},
		},
		{
			name:     "ShouldDeduplicateOriginsWhichNormalizeToTheSameValue",
			have:     []string{"https://example.com", "https://example.com/", "https://example.com/path"},
			expected: []string{"https://example.com"},
		},
		{
			name:     "ShouldAcceptAnHTTPOrigin",
			have:     []string{"http://localhost:8080"},
			expected: []string{"http://localhost:8080"},
		},
		{
			name: "ShouldRejectNoOrigins",
			have: nil,
			err:  "error validating related origins: at least one origin is required",
		},
		{
			name: "ShouldRejectAnEmptyOrigin",
			have: []string{""},
			err:  "error validating related origin '': the origin must be an absolute URL with a http or https scheme",
		},
		{
			name: "ShouldRejectAnOriginWithoutAScheme",
			have: []string{"example.com"},
			err:  "error validating related origin 'example.com': the origin must be an absolute URL with a http or https scheme",
		},
		{
			name: "ShouldRejectANonHTTPScheme",
			have: []string{"ftp://example.com"},
			err:  "error validating related origin 'ftp://example.com': the scheme must be either http or https but it is 'ftp'",
		},
		{
			name: "ShouldRejectAnAndroidAPKKeyHash",
			have: []string{"android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			err:  "error validating related origin 'android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA': the scheme must be either http or https but it is 'android'",
		},
		{
			name:     "ShouldNormalizeAwayTheDefaultHTTPSPort",
			have:     []string{"https://example.com:443"},
			expected: []string{"https://example.com"},
		},
		{
			name:     "ShouldNormalizeAwayTheDefaultHTTPPort",
			have:     []string{"http://example.com:80"},
			expected: []string{"http://example.com"},
		},
		{
			name:     "ShouldNormalizeAwayAnEmptyPort",
			have:     []string{"https://example.com:"},
			expected: []string{"https://example.com"},
		},
		{
			name:     "ShouldNormalizeAwayAnEmptyPortOfAnIPv6Literal",
			have:     []string{"https://[::1]:"},
			expected: []string{"https://[::1]"},
		},
		{
			name:     "ShouldDeduplicateAnEmptyPortAgainstNoPort",
			have:     []string{"https://example.com", "https://example.com:"},
			expected: []string{"https://example.com"},
		},
		{
			name: "ShouldRejectAPortAboveTheMaximum",
			have: []string{"https://example.com:65536"},
			err:  "error validating related origin 'https://example.com:65536': the port must be no greater than 65535 but it is '65536'",
		},
		{
			name: "ShouldRejectAPortWhichOverflows",
			have: []string{"https://example.com:999999999999999999999"},
			err:  "error validating related origin 'https://example.com:999999999999999999999': the port must be no greater than 65535 but it is '999999999999999999999'",
		},
		{
			name: "ShouldRejectAPortAboveTheMaximumOfAnIPv6Literal",
			have: []string{"https://[::1]:70000"},
			err:  "error validating related origin 'https://[::1]:70000': the port must be no greater than 65535 but it is '70000'",
		},
		{
			name:     "ShouldAcceptTheMaximumPort",
			have:     []string{"https://example.com:65535"},
			expected: []string{"https://example.com:65535"},
		},
		{
			name: "ShouldRejectAPortWithoutAHost",
			have: []string{"https://:8443"},
			err:  "error validating related origin 'https://:8443': the origin must have a host component",
		},
		{
			name:     "ShouldPreserveTheBracketsOfAnIPv6Literal",
			have:     []string{"https://[::1]:443", "https://[::1]:8443"},
			expected: []string{"https://[::1]", "https://[::1]:8443"},
		},
		{
			name:     "ShouldLowercaseTheSchemeAndHost",
			have:     []string{"HTTPS://EXAMPLE.COM"},
			expected: []string{"https://example.com"},
		},
		{
			name: "ShouldRejectAnOriginWithoutAHost",
			have: []string{"https:///path"},
			err:  "error validating related origin 'https:///path': the origin must have a host component",
		},
		{
			name: "ShouldRejectMoreLabelsThanClientsProcess",
			have: []string{"https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com", "https://f.com"},
			err:  "error validating related origins: the origins have 6 distinct registrable domain labels but clients only process 5 of them, so origins beyond that limit are ignored",
		},
		{
			name: "ShouldAcceptExactlyTheLabelLimit",
			have: []string{"https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com"},
			expected: []string{
				"https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			related, err := NewRelatedOrigins(tc.have...)

			if tc.err != "" {
				assert.Nil(t, related)
				assert.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, related)
			assert.Equal(t, tc.expected, related.Origins)
		})
	}
}

// TestNewRelatedOriginsWithLabeler covers the label derivation being replaceable, which is how a deployment using a
// multi-label public suffix obtains exact label counting without this module depending on a public suffix list.
func TestNewRelatedOriginsWithLabeler(t *testing.T) {
	// Stands in for a public suffix list backed labeler: every origin below has the registrable domain label
	// 'example', so the six of them cost one label rather than six.
	labeler := func(origin string) (label string, err error) {
		return "example", nil
	}

	// Every one of these is the registrable domain 'example' under a multi-label public suffix, so a client counts
	// one label for the set. The default labeler sees six distinct labels instead: co, com, ne, or, ac and gov.
	origins := []string{
		"https://example.co.uk", "https://example.com.au", "https://example.ne.jp",
		"https://example.or.kr", "https://example.ac.nz", "https://example.gov.uk",
	}

	t.Run("ShouldRejectTheseOriginsWithTheDefaultLabeler", func(t *testing.T) {
		related, err := NewRelatedOrigins(origins...)

		assert.Nil(t, related)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "distinct registrable domain labels")
	})

	t.Run("ShouldAcceptTheseOriginsWithAPublicSuffixLabeler", func(t *testing.T) {
		related, err := NewRelatedOriginsWithLabeler(labeler, origins...)

		require.NoError(t, err)
		require.NotNil(t, related)
		assert.Equal(t, origins, related.Origins)
	})

	t.Run("ShouldPropagateALabelerError", func(t *testing.T) {
		related, err := NewRelatedOriginsWithLabeler(func(origin string) (string, error) {
			return "", errors.New("no label for you")
		}, "https://example.com")

		assert.Nil(t, related)
		assert.EqualError(t, err, "error validating related origin 'https://example.com': error determining the registrable domain label: no label for you")
	})

	t.Run("ShouldUseTheDefaultLabelerWhenNil", func(t *testing.T) {
		related, err := NewRelatedOriginsWithLabeler(nil, "https://example.com")

		require.NoError(t, err)
		require.NotNil(t, related)
		assert.Equal(t, []string{"https://example.com"}, related.Origins)
	})
}

func TestDefaultRelatedOriginLabeler(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected string
		err      string
	}{
		{name: "ShouldUseTheRegistrableLabel", have: "https://example.com", expected: "example"},
		{name: "ShouldIgnoreASubdomain", have: "https://www.example.com", expected: "example"},
		{name: "ShouldIgnoreAPort", have: "https://example.com:8443", expected: "example"},
		{name: "ShouldLowercaseTheLabel", have: "https://EXAMPLE.com", expected: "example"},
		{name: "ShouldUseTheWholeHostWhenSingleLabel", have: "http://localhost:8080", expected: "localhost"},
		{name: "ShouldUseTheWholeHostForAnIPv4Address", have: "https://127.0.0.1", expected: "127.0.0.1"},
		{name: "ShouldUseTheWholeHostForAnIPv6Address", have: "https://[::1]:8443", expected: "::1"},

		// The documented imprecision of the default labeler: a multi-label public suffix yields the suffix's own
		// leading label rather than the registrable one, which over-counts against the limit.
		{name: "ShouldOverCountAMultiLabelPublicSuffix", have: "https://example.co.uk", expected: "co"},

		{name: "ShouldErrorOnAnUnparseableOrigin", have: "https://exa mple.com", err: "error parsing origin"},
		{name: "ShouldErrorOnAnOriginWithoutAHost", have: "https:///path", err: "the origin has no host component"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			label, err := DefaultRelatedOriginLabeler(tc.have)

			if tc.err != "" {
				assert.Empty(t, label)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, label)
		})
	}
}

func TestRelatedOriginsBytes(t *testing.T) {
	t.Run("ShouldProduceTheWellKnownDocument", func(t *testing.T) {
		related, err := NewRelatedOrigins("https://example.com", "https://example.com.au")
		require.NoError(t, err)

		data, err := related.Bytes()

		require.NoError(t, err)
		assert.Equal(t, `{"origins":["https://example.com","https://example.com.au"]}`, string(data))
	})

	t.Run("ShouldProduceAnEmptyArrayForTheZeroValue", func(t *testing.T) {
		data, err := RelatedOrigins{}.Bytes()

		require.NoError(t, err)
		assert.Equal(t, `{"origins":[]}`, string(data))
	})
}

func TestRelatedOriginsWriteTo(t *testing.T) {
	t.Run("ShouldWriteTheDocumentAndReportTheCount", func(t *testing.T) {
		related, err := NewRelatedOrigins("https://example.com")
		require.NoError(t, err)

		builder := &strings.Builder{}

		n, err := related.WriteTo(builder)

		require.NoError(t, err)
		assert.Equal(t, `{"origins":["https://example.com"]}`, builder.String())
		assert.Equal(t, int64(builder.Len()), n)
	})

	t.Run("ShouldSatisfyIOWriterTo", func(t *testing.T) {
		related, err := NewRelatedOrigins("https://example.com")
		require.NoError(t, err)

		var writerTo io.WriterTo = related

		builder := &strings.Builder{}

		_, err = writerTo.WriteTo(builder)

		require.NoError(t, err)
		assert.Equal(t, `{"origins":["https://example.com"]}`, builder.String())
	})

	t.Run("ShouldPropagateAWriteError", func(t *testing.T) {
		related, err := NewRelatedOrigins("https://example.com")
		require.NoError(t, err)

		n, err := related.WriteTo(&testErrorWriter{err: errors.New("disk on fire")})

		assert.EqualError(t, err, "disk on fire")
		assert.Equal(t, int64(0), n)
	})
}

func TestRelatedOriginsWriteResponse(t *testing.T) {
	t.Run("ShouldWriteTheDocumentWithTheJSONContentType", func(t *testing.T) {
		related, err := NewRelatedOrigins("https://example.com")
		require.NoError(t, err)

		recorder := httptest.NewRecorder()

		require.NoError(t, related.WriteResponse(recorder))

		result := recorder.Result()

		defer result.Body.Close()

		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "application/json", result.Header.Get("Content-Type"))
		assert.Equal(t, `{"origins":["https://example.com"]}`, recorder.Body.String())
	})
}

func TestRelatedOriginsServeHTTP(t *testing.T) {
	related, err := NewRelatedOrigins("https://example.com")
	require.NoError(t, err)

	t.Run("ShouldSatisfyHTTPHandler", func(t *testing.T) {
		var handler http.Handler = related

		assert.NotNil(t, handler)
	})

	t.Run("ShouldServeAGet", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		related.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, WellKnownPathWebAuthn, nil))

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		assert.Equal(t, `{"origins":["https://example.com"]}`, recorder.Body.String())
	})

	t.Run("ShouldServeAHead", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		related.ServeHTTP(recorder, httptest.NewRequest(http.MethodHead, WellKnownPathWebAuthn, nil))

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		assert.Empty(t, recorder.Body.String())
	})

	t.Run("ShouldRejectOtherMethodsWithAnAllowHeader", func(t *testing.T) {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			t.Run(method, func(t *testing.T) {
				recorder := httptest.NewRecorder()

				related.ServeHTTP(recorder, httptest.NewRequest(method, WellKnownPathWebAuthn, nil))

				assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
				assert.Equal(t, "GET, HEAD", recorder.Header().Get("Allow"))
				assert.Empty(t, recorder.Body.String())
			})
		}
	})

	t.Run("ShouldMountOnAServeMuxAtTheWellKnownPath", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.Handle(WellKnownPathWebAuthn, related)

		recorder := httptest.NewRecorder()

		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, WellKnownPathWebAuthn, nil))

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, `{"origins":["https://example.com"]}`, recorder.Body.String())
	})
}

func TestIsOpaqueOrigin(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected bool
	}{
		{name: "ShouldNotConsiderAnHTTPSOriginOpaque", have: "https://example.com", expected: false},
		{name: "ShouldNotConsiderAnHTTPOriginOpaque", have: "http://localhost:8080", expected: false},
		{name: "ShouldNotConsiderAnUppercaseSchemeOpaque", have: "HTTPS://example.com", expected: false},
		{name: "ShouldNotConsiderAnIPv6LiteralOpaque", have: "https://[::1]:8443", expected: false},
		{name: "ShouldConsiderAnAndroidKeyHashOpaque", have: "android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk", expected: true},
		{name: "ShouldConsiderAnUnknownSchemeOpaque", have: "ios:bundle-id:com.example.app", expected: true},
		{name: "ShouldConsiderASchemelessValueOpaque", have: "example.com", expected: true},
		{name: "ShouldConsiderAnHTTPSURLWithoutAHostOpaque", have: "https:///path", expected: true},
		{name: "ShouldConsiderAnUnparseableValueOpaque", have: "https://exa mple.com", expected: true},
		{name: "ShouldConsiderAnEmptyValueOpaque", have: "", expected: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsOpaqueOrigin(tc.have))
		})
	}
}

func TestIsKnownOpaqueOrigin(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected bool
	}{
		{name: "ShouldKnowAnAndroidKeyHash", have: "android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk", expected: true},
		{name: "ShouldKnowAnAndroidKeyHashSHA256", have: "android:apk-key-hash-sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", expected: true},
		{name: "ShouldKnowAnAndroidKeyID", have: "android:apk-key-id:2jmj7l5rSw0yVb-vlWAYkK-YBwk", expected: true},
		{name: "ShouldKnowAnIOSBundleID", have: "ios:bundle-id:com.example.app", expected: true},
		{name: "ShouldKnowAnIOSBundleKey", have: "ios:bundle-key:2jmj7l5rSw0yVb-vlWAYkK-YBwk", expected: true},
		{name: "ShouldKnowAChromeExtension", have: "chrome-extension://mbniclmhobmnbdlbpiphghaielnnpgdp", expected: true},
		{name: "ShouldKnowAMozExtension", have: "moz-extension://d56a5b99-51b6-4e83-ab23-796216191c9d", expected: true},
		{name: "ShouldKnowAFileOrigin", have: "file://", expected: true},
		{name: "ShouldKnowAMSAppXOrigin", have: "ms-appx://microsoft.windowscalculator_8wekyb3d8bbwe", expected: true},
		{name: "ShouldNotKnowAnAndroidKeyHashWithoutAValue", have: "android:apk-key-hash:", expected: false},
		{name: "ShouldNotKnowAnIOSBundleIDWithoutAValue", have: "ios:bundle-id:", expected: false},
		{name: "ShouldNotKnowAChromeExtensionWithoutAnID", have: "chrome-extension://", expected: false},
		{name: "ShouldNotKnowAnUppercasePrefix", have: "ANDROID:APK-KEY-HASH:2jmj7l5rSw0yVb-vlWAYkK-YBwk", expected: false},
		{name: "ShouldNotKnowAnUppercaseFileOrigin", have: "FILE://", expected: false},
		{name: "ShouldNotKnowAnAndroidKeyHashWithASingleColon", have: "android:apk-key-hash2jmj7l5rSw0yVb-vlWAYkK-YBwk", expected: false},
		{name: "ShouldNotKnowAnotherNativeScheme", have: "ios:team-id:ABCDE12345", expected: false},
		{name: "ShouldNotKnowAnotherExtensionScheme", have: "safari-web-extension://d56a5b99-51b6-4e83-ab23-796216191c9d", expected: false},
		{name: "ShouldNotKnowAnHTTPSOrigin", have: "https://example.com", expected: false},
		{name: "ShouldNotKnowAnHTTPSOriginWithoutAHost", have: "https:///path", expected: false},
		{name: "ShouldNotKnowAnHTTPSOriginWithAnOutOfRangePort", have: "https://example.com:99999", expected: false},
		{name: "ShouldNotKnowASchemelessValue", have: "example.com", expected: false},
		{name: "ShouldNotKnowAnEmptyValue", have: "", expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsKnownOpaqueOrigin(tc.have))
		})
	}
}

func TestOpaqueOriginPrefixes(t *testing.T) {
	expected := []string{
		OpaqueOriginPrefixAndroidAPKKeyHash,
		OpaqueOriginPrefixAndroidAPKKeyHashSHA256,
		OpaqueOriginPrefixAndroidAPKKeyID,
		OpaqueOriginPrefixIOSBundleID,
		OpaqueOriginPrefixIOSBundleKey,
		OpaqueOriginPrefixChromeExtension,
		OpaqueOriginPrefixMozExtension,
		OpaqueOriginPrefixFile,
		OpaqueOriginPrefixMSAppX,
	}

	prefixes := OpaqueOriginPrefixes()

	assert.Equal(t, expected, prefixes)

	prefixes[0] = "example:"

	assert.Equal(t, expected, OpaqueOriginPrefixes())
	assert.True(t, IsKnownOpaqueOrigin("android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"))
}

type testErrorWriter struct {
	err error
}

func (w *testErrorWriter) Write(p []byte) (n int, err error) {
	return 0, w.err
}
