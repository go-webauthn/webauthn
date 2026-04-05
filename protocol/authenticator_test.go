package protocol

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	noneAuthDataBase64 = "pkLSG3xtVeHOI8U5mCjSx0m/am7y/gPMnhDN9O1ttItBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMAxl6G32ykWaLrv/ouCs5HoGsvONqBtOb7ZmyMs8K8PccnwyyqPzWn/yZuyQmQBguvjYSvH6gDBlFG65quUDCSlAQIDJiABIVggyJGP+ra/u/eVjqN4OeYXUShRWxrEeC6Sb5/bZmJ9q8MiWCCHIkRdg5oRb1RHoFVYUpogcjlObCKFsV1ls1T+uUc6rA=="
	attAuthDataBase64  = "lWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4/Xy7IpvdRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIniszxcGnhupdPFOHJIm6dscrWCC2h8xHicBMu91THD0kdOdB0QQtkaEn+6KfsfT1o3NmmFT8YfXrG734WfVSmlAQIDJiABIVggyoHHeiUw5aSbt8/GsL9zaqZGRzV26A4y3CnCGUhVXu4iWCBMnc8za5xgPzIygngAv9W+vZTMGJwwZcM4sjiqkcb/1g=="
)

func TestAuthenticatorFlags_UserPresent(t *testing.T) {
	testCases := []struct {
		name     string
		flag     AuthenticatorFlags
		expected bool
	}{
		{
			"Present",
			AuthenticatorFlags(0x01),
			true,
		},
		{
			"Missing",
			AuthenticatorFlags(0x10),
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.flag.UserPresent())
		})
	}
}

func TestAuthenticatorFlags_UserVerified(t *testing.T) {
	testCases := []struct {
		name     string
		flag     AuthenticatorFlags
		expected bool
	}{
		{
			"Present",
			AuthenticatorFlags(0x04),
			true,
		},
		{
			"Missing",
			AuthenticatorFlags(0x02),
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.flag.UserVerified())
		})
	}
}

func TestAuthenticatorFlags_HasAttestedCredentialData(t *testing.T) {
	testCases := []struct {
		name     string
		flag     AuthenticatorFlags
		expected bool
	}{
		{
			"Present",
			AuthenticatorFlags(0x40),
			true,
		},
		{
			"Missing",
			AuthenticatorFlags(0x01),
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.flag.HasAttestedCredentialData())
		})
	}
}

func TestAuthenticatorFlags_HasExtensions(t *testing.T) {
	testCases := []struct {
		name     string
		flag     AuthenticatorFlags
		expected bool
	}{
		{
			"Present",
			AuthenticatorFlags(0x80),
			true,
		},
		{
			"Missing",
			AuthenticatorFlags(0x01),
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.flag.HasExtensions())
		})
	}
}

func TestAuthenticatorData_Unmarshal(t *testing.T) {
	type fields struct {
		RPIDHash []byte
		Flags    AuthenticatorFlags
		Counter  uint32
		AttData  AttestedCredentialData
		ExtData  []byte
	}

	type args struct {
		rawAuthData []byte
	}

	noneAuthData, _ := base64.StdEncoding.DecodeString(noneAuthDataBase64)
	attAuthData, _ := base64.StdEncoding.DecodeString(attAuthDataBase64)

	// Empty data.
	badAuthData1 := []byte{}

	// Attested credential data missing.
	badAuthData2 := make([]byte, minAttestedAuthLength-1)
	copy(badAuthData2, attAuthData)

	// Flags not set but data exists.
	badAuthData3 := make([]byte, len(attAuthData))
	copy(badAuthData3, attAuthData)
	badAuthData3[32] &= 0b0011_1111

	// Extensions data missing.
	badAuthData4 := make([]byte, len(attAuthData))
	copy(badAuthData4, attAuthData)
	badAuthData4[32] |= 0b1000_0000

	// Leftover bytes.
	badAuthData5 := make([]byte, len(attAuthData)) //nolint:prealloc
	copy(badAuthData5, attAuthData)
	badAuthData5 = append(badAuthData5, []byte("Hello World")...)

	testCases := []struct {
		name   string
		fields fields
		args   args

		err        string
		errType    string
		errDetails string
		errInfo    string
	}{
		{
			name:   "NoneMarshallSuccessfully",
			fields: fields{},
			args: args{
				noneAuthData,
			},
		},
		{
			name:   "AttDataMarshallSuccessfully",
			fields: fields{},
			args: args{
				attAuthData,
			},
		},
		{
			name:   "AuthenticatorDataTooShort",
			fields: fields{},
			args: args{
				badAuthData1,
			},
			err:        "Authenticator data length too short",
			errType:    "invalid_request",
			errDetails: "Authenticator data length too short",
			errInfo:    fmt.Sprintf("Expected data greater than %d bytes. Got %d bytes", minAuthDataLength, len(badAuthData1)),
		},
		{
			name:   "AttestedCredentialMissing",
			fields: fields{},
			args: args{
				badAuthData2,
			},
			err:        "Attested credential flag set but data is missing",
			errType:    "invalid_request",
			errDetails: "Attested credential flag set but data is missing",
			errInfo:    "",
		},
		{
			name:   "AttestedCredentialMissing",
			fields: fields{},
			args: args{
				badAuthData3,
			},
			err:        "Attested credential flag not set",
			errType:    "invalid_request",
			errDetails: "Attested credential flag not set",
			errInfo:    "",
		},
		{
			name:   "ExtensionsDataMissing",
			fields: fields{},
			args: args{
				badAuthData4,
			},
			err:        "Extensions flag set but extensions data is missing",
			errType:    "invalid_request",
			errDetails: "Extensions flag set but extensions data is missing",
			errInfo:    "",
		},
		{
			name:   "LeftoverBytes",
			fields: fields{},
			args: args{
				badAuthData5,
			},
			err:        "Leftover bytes decoding AuthenticatorData",
			errType:    "invalid_request",
			errDetails: "Leftover bytes decoding AuthenticatorData",
			errInfo:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &AuthenticatorData{
				RPIDHash: tc.fields.RPIDHash,
				Flags:    tc.fields.Flags,
				Counter:  tc.fields.Counter,
				AttData:  tc.fields.AttData,
				ExtData:  tc.fields.ExtData,
			}

			err := a.Unmarshal(tc.args.rawAuthData)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				AssertIsProtocolError(t, err, tc.errType, tc.errDetails, tc.errInfo)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthenticatorData_unmarshalAttestedData(t *testing.T) {
	type fields struct {
		RPIDHash []byte
		Flags    AuthenticatorFlags
		Counter  uint32
		AttData  AttestedCredentialData
		ExtData  []byte
	}

	type args struct {
		rawAuthData []byte
	}

	noneAuthData, _ := base64.StdEncoding.DecodeString(noneAuthDataBase64)
	attAuthData, _ := base64.StdEncoding.DecodeString(attAuthDataBase64)

	// Data length too short.
	badAuthData1 := make([]byte, len(attAuthData))
	copy(badAuthData1, attAuthData)
	binary.BigEndian.PutUint16(badAuthData1[53:], 256)

	// ID length too long.
	badAuthData2 := make([]byte, len(attAuthData)+maxCredentialIDLength+1)
	copy(badAuthData2, attAuthData)
	binary.BigEndian.PutUint16(badAuthData2[53:], maxCredentialIDLength+1)

	// Malformed public key.
	badAuthData3 := make([]byte, 119) //nolint:prealloc
	copy(badAuthData3, attAuthData[:119])

	badData, _ := hex.DecodeString("83FF20030102")
	badAuthData3 = append(badAuthData3, badData...)

	testCases := []struct {
		name       string
		fields     fields
		args       args
		err        string
		errType    string
		errDetails string
		errInfo    string
	}{
		{
			name:   "None Marshall Successfully",
			fields: fields{},
			args: args{
				noneAuthData,
			},
		},
		{
			name:   "Att Data Marshall Successfully",
			fields: fields{},
			args: args{
				attAuthData,
			},
		},
		{
			name:   "Data length too short",
			fields: fields{},
			args: args{
				badAuthData1,
			},
			err:        "Authenticator attestation data length too short",
			errType:    "invalid_request",
			errDetails: "Authenticator attestation data length too short",
			errInfo:    "",
		},
		{
			name:   "ID length too long",
			fields: fields{},
			args: args{
				badAuthData2,
			},
			err:        "Authenticator attestation data credential id length too long",
			errType:    "invalid_request",
			errDetails: "Authenticator attestation data credential id length too long",
			errInfo:    "",
		},
		{
			name:   "Could not unmarshal Credential Public Key",
			fields: fields{},
			args: args{
				badAuthData3,
			},
			err:        "Could not unmarshal Credential Public Key: cbor: unexpected \"break\" code",
			errType:    "invalid_request",
			errDetails: "Could not unmarshal Credential Public Key: cbor: unexpected \"break\" code",
			errInfo:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := &AuthenticatorData{
				RPIDHash: tc.fields.RPIDHash,
				Flags:    tc.fields.Flags,
				Counter:  tc.fields.Counter,
				AttData:  tc.fields.AttData,
				ExtData:  tc.fields.ExtData,
			}

			err := actual.unmarshalAttestedData(tc.args.rawAuthData)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				AssertIsProtocolError(t, err, tc.errType, tc.errDetails, tc.errInfo)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthenticatorFlags_HasBackupEligible(t *testing.T) {
	testCases := []struct {
		name     string
		flag     AuthenticatorFlags
		expected bool
	}{
		{
			name:     "Present",
			flag:     FlagBackupEligible,
			expected: true,
		},
		{
			name:     "PresentWithOtherFlags",
			flag:     FlagBackupEligible | FlagUserPresent,
			expected: true,
		},
		{
			name:     "Missing",
			flag:     FlagUserPresent,
			expected: false,
		},
		{
			name:     "Zero",
			flag:     0,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.flag.HasBackupEligible())
		})
	}
}

func TestAuthenticatorFlags_HasBackupState(t *testing.T) {
	testCases := []struct {
		name     string
		flag     AuthenticatorFlags
		expected bool
	}{
		{
			name:     "Present",
			flag:     FlagBackupState,
			expected: true,
		},
		{
			name:     "PresentWithOtherFlags",
			flag:     FlagBackupState | FlagBackupEligible,
			expected: true,
		},
		{
			name:     "Missing",
			flag:     FlagUserPresent,
			expected: false,
		},
		{
			name:     "Zero",
			flag:     0,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.flag.HasBackupState())
		})
	}
}

func TestResidentKeyRequired(t *testing.T) {
	result := ResidentKeyRequired()

	require.NotNil(t, result)
	assert.True(t, *result)
}

func TestResidentKeyNotRequired(t *testing.T) {
	result := ResidentKeyNotRequired()

	require.NotNil(t, result)
	assert.False(t, *result)
}

func TestAuthenticatorData_Verify(t *testing.T) {
	type fields struct {
		RPIDHash []byte
		Flags    AuthenticatorFlags
		Counter  uint32
		AttData  AttestedCredentialData
		ExtData  []byte
	}

	type args struct {
		rpIdHash                 []byte
		userVerificationRequired bool
		userPresenceRequired     bool
	}

	testCases := []struct {
		name       string
		fields     fields
		args       args
		err        string
		errType    string
		errDetails string
		errInfo    string
	}{
		{
			name: "Success",
			fields: fields{
				RPIDHash: []byte{1, 2, 3},
				Flags:    AuthenticatorFlags(0x05),
			},
			args: args{
				rpIdHash: []byte{1, 2, 3},
			},
			err: "",
		},
		{
			name: "RP hash mismatch",
			fields: fields{
				RPIDHash: []byte{0xff},
			},
			args: args{
				rpIdHash: []byte{0xaa},
			},
			err:        "Error validating the authenticator response",
			errType:    "verification_error",
			errDetails: "Error validating the authenticator response",
			errInfo:    "RP Hash mismatch. Expected ff and Received aa",
		},
		{
			name: "UP flag not set",
			fields: fields{
				RPIDHash: []byte{1, 2, 3},
				Flags:    AuthenticatorFlags(0x04),
			},
			args: args{
				rpIdHash:             []byte{1, 2, 3},
				userPresenceRequired: true,
			},
			err:        "Error validating the authenticator response",
			errType:    "verification_error",
			errDetails: "Error validating the authenticator response",
			errInfo:    "User presence required but flag not set by authenticator",
		},
		{
			name: "User verification required",
			fields: fields{
				RPIDHash: []byte{1, 2, 3},
				Flags:    AuthenticatorFlags(0x01),
			},
			args: args{
				rpIdHash:                 []byte{1, 2, 3},
				userVerificationRequired: true,
				userPresenceRequired:     true,
			},
			err:        "Error validating the authenticator response",
			errType:    "verification_error",
			errDetails: "Error validating the authenticator response",
			errInfo:    "User verification required but flag not set by authenticator",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &AuthenticatorData{
				RPIDHash: tc.fields.RPIDHash,
				Flags:    tc.fields.Flags,
				Counter:  tc.fields.Counter,
				AttData:  tc.fields.AttData,
				ExtData:  tc.fields.ExtData,
			}

			err := a.Verify(tc.args.rpIdHash, nil, tc.args.userVerificationRequired, tc.args.userPresenceRequired)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				AssertIsProtocolError(t, err, tc.errType, tc.errDetails, tc.errInfo)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
