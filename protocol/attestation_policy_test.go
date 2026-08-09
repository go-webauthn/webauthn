package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAndroidKeyAuthorizationScopeUnion(t *testing.T) {
	testCases := []struct {
		name     string
		scope    AndroidKeyAuthorizationScope
		expected bool
	}{
		{
			// The zero value must resolve to the restrictive branch so a policy which was never passed through
			// config validation is still safe.
			name:     "ShouldTreatDefaultAsTEEEnforced",
			scope:    AndroidKeyAuthorizationScopeDefault,
			expected: false,
		},
		{
			name:     "ShouldTreatTEEEnforcedAsTEEEnforced",
			scope:    AndroidKeyAuthorizationScopeTEEEnforced,
			expected: false,
		},
		{
			name:     "ShouldTreatUnionAsUnion",
			scope:    AndroidKeyAuthorizationScopeUnion,
			expected: true,
		},
		{
			// A value outside the defined set resolves to the restrictive branch rather than the permissive one.
			name:     "ShouldTreatUnknownAsTEEEnforced",
			scope:    AndroidKeyAuthorizationScope(99),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.scope.union())
		})
	}
}

func TestAttestationPolicyZeroValue(t *testing.T) {
	var policy AttestationPolicy

	assert.Equal(t, AndroidKeyAuthorizationScopeDefault, policy.AndroidKey.AuthorizationScope)
	assert.False(t, policy.AndroidKey.AuthorizationScope.union())
}
