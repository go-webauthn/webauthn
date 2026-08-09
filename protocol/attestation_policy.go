package protocol

// AttestationPolicy carries the Relying Party policy decisions which §8 of the specification delegates to the
// Relying Party rather than fixing. The zero value selects the most restrictive behavior available for each
// policy it carries.
type AttestationPolicy struct {
	// AndroidKey configures the Android Key Attestation Statement Format verification procedure.
	AndroidKey AndroidKeyPolicy
}

// AndroidKeyPolicy configures the Android Key Attestation Statement Format verification procedure.
//
// Specification: §8.4. Android Key Attestation Statement Format (https://www.w3.org/TR/webauthn/#sctn-android-key-attestation)
type AndroidKeyPolicy struct {
	// AuthorizationScope selects the authorization lists of the attestation certificate extension which the origin
	// and purpose requirements are evaluated against.
	AuthorizationScope AndroidKeyAuthorizationScope
}

// AndroidKeyAuthorizationScope selects the authorization lists of the Android key attestation certificate
// extension which the §8.4 origin and purpose requirements are evaluated against.
//
// §8.4 assigns this choice to the Relying Party: "For the following, use only the teeEnforced authorization list
// if the RP wants to accept only keys from a trusted execution environment, otherwise use the union of
// teeEnforced and softwareEnforced."
//
// Specification: §8.4. Android Key Attestation Statement Format (https://www.w3.org/TR/webauthn/#sctn-android-key-attestation)
type AndroidKeyAuthorizationScope int

const (
	// AndroidKeyAuthorizationScopeDefault is the zero value of [AndroidKeyAuthorizationScope] and has no matching
	// rule in §8.4. It evaluates as [AndroidKeyAuthorizationScopeTEEEnforced] wherever it is used. webauthn.Config
	// rewrites it to that explicit constant during validation, so a Relying Party can tell an unset field apart
	// from a deliberate choice of the same scope.
	AndroidKeyAuthorizationScopeDefault AndroidKeyAuthorizationScope = iota

	// AndroidKeyAuthorizationScopeTEEEnforced evaluates the origin and purpose requirements against the teeEnforced
	// authorization list alone, accepting only keys generated within a trusted execution environment.
	AndroidKeyAuthorizationScopeTEEEnforced

	// AndroidKeyAuthorizationScopeUnion evaluates the origin and purpose requirements against the union of the
	// teeEnforced and softwareEnforced authorization lists, which additionally accepts software backed keys.
	AndroidKeyAuthorizationScopeUnion
)

// union returns true when the scope evaluates the origin and purpose requirements against both authorization
// lists. Every other value, including the zero value and any value outside the defined set, evaluates them
// against teeEnforced alone so that an unset or malformed policy is the restrictive one.
func (s AndroidKeyAuthorizationScope) union() bool {
	return s == AndroidKeyAuthorizationScopeUnion
}
