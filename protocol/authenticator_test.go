package protocol

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestAuthenticatorFlags_UserPresent(t *testing.T) {
	var goodByte byte = 0x01
	var badByte byte = 0x10
	tests := []struct {
		name string
		flag AuthenticatorFlags
		want bool
	}{
		{
			"Present",
			AuthenticatorFlags(goodByte),
			true,
		},
		{
			"Missing",
			AuthenticatorFlags(badByte),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.UserPresent(); got != tt.want {
				t.Errorf("AuthenticatorFlags.UserPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticatorFlags_UserVerified(t *testing.T) {
	var goodByte byte = 0x04
	var badByte byte = 0x02
	tests := []struct {
		name string
		flag AuthenticatorFlags
		want bool
	}{
		{
			"Present",
			AuthenticatorFlags(goodByte),
			true,
		},
		{
			"Missing",
			AuthenticatorFlags(badByte),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.UserVerified(); got != tt.want {
				t.Errorf("AuthenticatorFlags.UserVerified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticatorFlags_HasAttestedCredentialData(t *testing.T) {
	var goodByte byte = 0x40
	var badByte byte = 0x01
	tests := []struct {
		name string
		flag AuthenticatorFlags
		want bool
	}{
		{
			"Present",
			AuthenticatorFlags(goodByte),
			true,
		},
		{
			"Missing",
			AuthenticatorFlags(badByte),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.HasAttestedCredentialData(); got != tt.want {
				t.Errorf("AuthenticatorFlags.HasAttestedCredentialData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticatorFlags_HasExtensions(t *testing.T) {
	var goodByte byte = 0x80
	var badByte byte = 0x01
	tests := []struct {
		name string
		flag AuthenticatorFlags
		want bool
	}{
		{
			"Present",
			AuthenticatorFlags(goodByte),
			true,
		},
		{
			"Missing",
			AuthenticatorFlags(badByte),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.HasExtensions(); got != tt.want {
				t.Errorf("AuthenticatorFlags.HasExtensions() = %v, want %v", got, tt.want)
			}
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

	noneAuthData, _ := base64.StdEncoding.DecodeString("pkLSG3xtVeHOI8U5mCjSx0m/am7y/gPMnhDN9O1TCItBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMAxl6G32ykWaLrv/ouCs5HoGsvONqBtOb7ZmyMs8K8PccnwyyqPzWn/yZuyQmQBguvjYSvH6gDBlFG65quUDCSlAQIDJiABIVggyJGP+ra/u/eVjqN4OeYXUShRWxrEeC6Sb5/bZmJ9q8MiWCCHIkRdg5oRb1RHoFVYUpogcjlObCKFsV1ls1T+uUc6rA==")
	attAuthData, _ := base64.StdEncoding.DecodeString("lWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4/Xy7IpvdRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIniszxcGnhupdPFOHJIm6dscrWCC2h8xHicBMu91THD0kdOdB0QQtkaEn+6KfsfT1o3NmmFT8YfXrG734WfVSmlAQIDJiABIVggyoHHeiUw5aSbt8/GsL9zaqZGRzV26A4y3CnCGUhVXu4iWCBMnc8za5xgPzIygngAv9W+vZTMGJwwZcM4sjiqkcb/1g==")

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"None Marshall Successfully",
			fields{},
			args{
				noneAuthData,
			},
			false,
		},
		{
			"Att Data Marshall Successfully",
			fields{},
			args{
				attAuthData,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthenticatorData{
				RPIDHash: tt.fields.RPIDHash,
				Flags:    tt.fields.Flags,
				Counter:  tt.fields.Counter,
				AttData:  tt.fields.AttData,
				ExtData:  tt.fields.ExtData,
			}
			if err := a.Unmarshal(tt.args.rawAuthData); (err != nil) != tt.wantErr {
				t.Errorf("AuthenticatorData.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
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
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthenticatorData{
				RPIDHash: tt.fields.RPIDHash,
				Flags:    tt.fields.Flags,
				Counter:  tt.fields.Counter,
				AttData:  tt.fields.AttData,
				ExtData:  tt.fields.ExtData,
			}
			if err := a.unmarshalAttestedData(tt.args.rawAuthData); (err != nil) != tt.wantErr {
				t.Errorf("AuthenticatorData.unmarshalAttestedData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_unmarshalCredentialPublicKey(t *testing.T) {
	type args struct {
		keyBytes []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unmarshalCredentialPublicKey(tt.args.keyBytes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unmarshalCredentialPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
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
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthenticatorData{
				RPIDHash: tt.fields.RPIDHash,
				Flags:    tt.fields.Flags,
				Counter:  tt.fields.Counter,
				AttData:  tt.fields.AttData,
				ExtData:  tt.fields.ExtData,
			}
			if err := a.Verify(tt.args.rpIdHash, nil, tt.args.userVerificationRequired); (err != nil) != tt.wantErr {
				t.Errorf("AuthenticatorData.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
