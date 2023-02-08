package protocol

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestCreateChallenge(t *testing.T) {
	tests := []struct {
		name    string
		want    Challenge
		wantErr bool
	}{
		{
			"Successfull Challenge Create",
			Challenge{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateChallenge()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.want = got
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateChallenge() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChallenge_String(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Errorf("CreateChallenge() error = %v", err)
		return
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(newChallenge)
	tests := []struct {
		name string
		c    Challenge
		want string
	}{
		{
			"Successful String",
			newChallenge,
			wantChallenge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("Challenge.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
