package webauthn

import (
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestMakeNewCredential(t *testing.T) {
	type args struct {
		c *protocol.ParsedCredentialCreationData
	}

	var tests []struct {
		name    string
		args    args
		want    *Credential
		wantErr bool
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeNewCredential(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeNewCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MakeNewCredential() = %v, want %v", got, tt.want)
			}
		})
	}
}
