package protocol

const (
	stmtX5C       = "x5c"
	stmtSignature = "sig"
	stmtAlgorithm = "alg"
	stmtVersion   = "ver"
	stmtECDAAKID  = "ecdaaKeyId"
	stmtCertInfo  = "certInfo"
	stmtPubArea   = "pubArea"
)

var (
	// internalRemappedAuthenticatorTransport handles remapping of AuthenticatorTransport values. Specifically it is
	// intentional on remapping only transports that never made recommendation but are being used in the wild. It
	// should not be used to handle transports that were ratified.
	internalRemappedAuthenticatorTransport = map[string]AuthenticatorTransport{
		// The Authenticator Transport 'hybrid' was previously named 'cable'; even if it was for a short period.
		"cable": Hybrid,
	}
)
