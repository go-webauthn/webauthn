package protocol

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseResponseLimitsBodyDrain(t *testing.T) {
	testCases := []struct {
		name  string
		parse func(request *http.Request) error
	}{
		{
			"ShouldLimitDrainForCreation",
			func(request *http.Request) error {
				_, err := ParseCredentialCreationResponse(request)

				return err
			},
		},
		{
			"ShouldLimitDrainForAssertion",
			func(request *http.Request) error {
				_, err := ParseCredentialRequestResponse(request)

				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := &endlessBody{}

			request, err := http.NewRequest(http.MethodPost, "https://example.com", body)

			require.NoError(t, err)

			assert.Error(t, tc.parse(request))
			assert.True(t, body.closed)
			assert.LessOrEqual(t, body.read, int64(bodyDrainLimit+64<<10))
		})
	}
}

func TestParseResponseLimitsBodyRead(t *testing.T) {
	testCases := []struct {
		name    string
		request bool
		details string
		parse   func(body io.Reader) error
	}{
		{
			"ShouldLimitReadForCreationBody",
			false,
			"Parse error for Registration",
			func(body io.Reader) error {
				_, err := ParseCredentialCreationResponseBody(body)

				return err
			},
		},
		{
			"ShouldLimitReadForAssertionBody",
			false,
			"Parse error for Assertion",
			func(body io.Reader) error {
				_, err := ParseCredentialRequestResponseBody(body)

				return err
			},
		},
		{
			"ShouldLimitReadForCreationRequest",
			true,
			"Parse error for Registration",
			func(body io.Reader) error {
				request, err := http.NewRequest(http.MethodPost, "https://example.com", body)
				if err != nil {
					return err
				}

				_, err = ParseCredentialCreationResponse(request)

				return err
			},
		},
		{
			"ShouldLimitReadForAssertionRequest",
			true,
			"Parse error for Assertion",
			func(body io.Reader) error {
				request, err := http.NewRequest(http.MethodPost, "https://example.com", body)
				if err != nil {
					return err
				}

				_, err = ParseCredentialRequestResponse(request)

				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("ShouldFailParseAtLimit", func(t *testing.T) {
				body := &unterminatedBody{size: bodyReadLimit}

				err := tc.parse(body)

				var e *Error

				require.ErrorAs(t, err, &e)
				assert.Equal(t, tc.details, e.Details)
				assert.NotErrorIs(t, err, errBodyTooLarge)
				assert.Equal(t, int64(bodyReadLimit), body.read)
			})

			t.Run("ShouldRejectOverLimit", func(t *testing.T) {
				body := &unterminatedBody{size: -1}

				err := tc.parse(body)

				var e *Error

				require.ErrorAs(t, err, &e)
				assert.Equal(t, "Request body is too large", e.Details)
				assert.ErrorIs(t, err, errBodyTooLarge)

				limit := int64(bodyReadLimit + 1)

				if tc.request {
					limit += bodyDrainLimit
				}

				assert.Equal(t, limit, body.read)
			})
		})
	}
}

func TestParseCollectedClientData(t *testing.T) {
	const clientData = `{"type":"webauthn.get","challenge":"AAAA","origin":"https://example.com"}`

	testCases := []struct {
		name string
		have []byte
		err  string
	}{
		{"ShouldParseObject", []byte(clientData), ""},
		{"ShouldParseObjectWithByteOrderMark", append([]byte{0xef, 0xbb, 0xbf}, clientData...), ""},
		{"ShouldParseObjectWithLeadingWhitespace", []byte(" \n" + clientData), ""},
		{"ShouldRejectNull", []byte("null"), "client data is not a JSON object"},
		{"ShouldRejectArray", []byte("[]"), "client data is not a JSON object"},
		{"ShouldRejectString", []byte(`"{}"`), "client data is not a JSON object"},
		{"ShouldRejectEmpty", nil, "client data is not a JSON object"},
		{"ShouldRejectByteOrderMarkOnly", []byte{0xef, 0xbb, 0xbf}, "client data is not a JSON object"},
		{"ShouldRejectTwoByteOrderMarks", append([]byte{0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf}, clientData...), "client data is not a JSON object"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actual CollectedClientData

			err := parseCollectedClientData(tc.have, &actual)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, CollectedClientData{Type: AssertCeremony, Challenge: "AAAA", Origin: "https://example.com"}, actual)
		})
	}
}

func TestAttestationResponseParseRejectsNullClientData(t *testing.T) {
	response := AuthenticatorAttestationResponse{
		AuthenticatorResponse: AuthenticatorResponse{ClientDataJSON: []byte("null")},
	}

	parsed, err := response.Parse()

	assert.Nil(t, parsed)

	var e *Error

	require.ErrorAs(t, err, &e)
	assert.Equal(t, "client data is not a JSON object", e.DevInfo)
}

type endlessBody struct {
	read   int64
	closed bool
}

func (b *endlessBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, io.ErrClosedPipe
	}

	for i := range p {
		p[i] = '!'
	}

	b.read += int64(len(p))

	return len(p), nil
}

func (b *endlessBody) Close() error {
	b.closed = true

	return nil
}

type unterminatedBody struct {
	size int64
	read int64
}

func (b *unterminatedBody) Read(p []byte) (int, error) {
	if b.size >= 0 && b.read >= b.size {
		return 0, io.EOF
	}

	if b.size >= 0 && int64(len(p)) > b.size-b.read {
		p = p[:b.size-b.read]
	}

	const prefix = `{"id":"`

	for i := range p {
		if offset := b.read + int64(i); offset < int64(len(prefix)) {
			p[i] = prefix[offset]
		} else {
			p[i] = 'a'
		}
	}

	b.read += int64(len(p))

	return len(p), nil
}
