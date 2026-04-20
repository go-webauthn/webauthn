package protocol

import "testing"

func TestIsISO3166Alpha2(t *testing.T) {
	testCases := []struct {
		name string
		code string
		want bool
	}{
		{"Assigned-US", "US", true},
		{"Assigned-AU", "AU", true},
		{"Assigned-DE", "DE", true},
		{"Assigned-ZW", "ZW", true},
		{"UserAssigned-AA", "AA", true},
		{"UserAssigned-ZZ", "ZZ", true},
		{"UserAssigned-QM", "QM", true},
		{"UserAssigned-QZ", "QZ", true},
		{"UserAssigned-XA", "XA", true},
		{"UserAssigned-XZ", "XZ", true},
		{"NotUserAssigned-QA", "QA", true},
		{"NotUserAssigned-QL", "QL", false},
		{"LowerCase-us", "us", false},
		{"MixedCase-Us", "Us", false},
		{"Alpha3-USA", "USA", false},
		{"Empty", "", false},
		{"SingleChar-U", "U", false},
		{"Numeric-01", "01", false},
		{"Whitespace", " US", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isISO3166Alpha2(tc.code); got != tc.want {
				t.Errorf("isISO3166Alpha2(%q) = %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}
