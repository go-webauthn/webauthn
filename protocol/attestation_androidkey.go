package protocol

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func init() {
	RegisterAttestationFormat(AttestationFormatAndroidKey, verifyAndroidKeyFormat)
}

// The android-key attestation statement looks like:
// $$attStmtType //= (
//
//	fmt: "android-key",
//	attStmt: androidStmtFormat
//
// )
//
//	androidStmtFormat = {
//			alg: COSEAlgorithmIdentifier,
//			sig: bytes,
//			x5c: [ credCert: bytes, * (caCert: bytes) ]
//	  }
//
// Specification: §8.4. Android Key Attestation Statement Format (https://www.w3.org/TR/webauthn/#sctn-android-key-attestation)
func verifyAndroidKeyFormat(att AttestationObject, clientDataHash []byte, _ metadata.Provider) (attestationType string, x5cs []any, err error) {
	// Given the verification procedure inputs attStmt, authenticatorData and clientDataHash, the verification procedure is as follows:
	// §8.4.1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract
	// the contained fields.

	if attAndroidKeyHardwareRootsCertPool == nil {
		pool := x509.NewCertPool()

		var cert *x509.Certificate

		if cert, err = x509.ParseCertificate(attAndroidKeyHardwareRoot3); err != nil {
			return "", nil, ErrAttestationFormat.WithDetails("Error occurred parsing android-key hardware root 3").WithError(err)
		} else {
			pool.AddCert(cert)
		}

		if cert, err = x509.ParseCertificate(attAndroidKeyHardwareRoot4); err != nil {
			return "", nil, ErrAttestationFormat.WithDetails("Error occurred parsing android-key hardware root 4").WithError(err)
		} else {
			pool.AddCert(cert)
		}

		attAndroidKeyHardwareRootsCertPool = pool
	}

	// Get the alg value - A COSEAlgorithmIdentifier containing the identifier of the algorithm
	// used to generate the attestation signature.
	alg, present := att.AttStatement[stmtAlgorithm].(int64)
	if !present {
		return "", nil, ErrAttestationFormat.WithDetails("Error retrieving alg value")
	}

	// Get the sig value - A byte string containing the attestation signature.
	sig, present := att.AttStatement[stmtSignature].([]byte)
	if !present {
		return "", nil, ErrAttestationFormat.WithDetails("Error retrieving sig value")
	}

	// If x5c is not present, return an error.
	x5c, x509present := att.AttStatement[stmtX5C].([]any)
	if !x509present {
		// Handle Basic Attestation steps for the x509 Certificate.
		return "", nil, ErrAttestationFormat.WithDetails("Error retrieving x5c value")
	}

	// §8.4.2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
	// using the public key in the first certificate in x5c with the algorithm specified in alg.
	attCertBytes, valid := x5c[0].([]byte)
	if !valid {
		return "", nil, ErrAttestation.WithDetails("Error getting certificate from x5c cert chain")
	}

	attCert, err := x509.ParseCertificate(attCertBytes)
	if err != nil {
		return "", nil, ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing certificate from ASN.1 data: %+v", err)).WithError(err)
	}

	signatureData := append(att.RawAuthData, clientDataHash...) //nolint:gocritic // This is intentional.

	if _, err = attCert.Verify(x509.VerifyOptions{Roots: attAndroidKeyHardwareRootsCertPool}); err != nil {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Signature validation error: %+v\n", err)).WithError(err)
	}

	coseAlg := webauthncose.COSEAlgorithmIdentifier(alg)
	if err = attCert.CheckSignature(webauthncose.SigAlgFromCOSEAlg(coseAlg), signatureData, sig); err != nil {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Signature validation error: %+v\n", err)).WithError(err)
	}

	// Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
	pubKey, err := webauthncose.ParsePublicKey(att.AuthData.AttData.CredentialPublicKey)
	if err != nil {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error parsing public key: %+v\n", err)).WithError(err)
	}

	e := pubKey.(webauthncose.EC2PublicKeyData)

	valid, err = e.Verify(signatureData, sig)
	if err != nil || !valid {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error parsing public key: %+v\n", err)).WithError(err)
	}

	// §8.4.3. Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
	// attCert.Extensions.
	var attExtBytes []byte

	for _, ext := range attCert.Extensions {
		if ext.Id.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}) {
			attExtBytes = ext.Value
		}
	}

	if len(attExtBytes) == 0 {
		return "", nil, ErrAttestationFormat.WithDetails("Attestation certificate extensions missing 1.3.6.1.4.1.11129.2.1.17")
	}

	// As noted in §8.4.1 (https://www.w3.org/TR/webauthn/#key-attstn-cert-requirements) the Android Key Attestation attestation certificate's
	// android key attestation certificate extension data is identified by the OID "1.3.6.1.4.1.11129.2.1.17".
	decoded := keyDescription{}

	if _, err = asn1.Unmarshal(attExtBytes, &decoded); err != nil {
		return "", nil, ErrAttestationFormat.WithDetails("Unable to parse Android key attestation certificate extensions").WithError(err)
	}

	// Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
	if !bytes.Equal(decoded.AttestationChallenge, clientDataHash) {
		return "", nil, ErrAttestationFormat.WithDetails("Attestation challenge not equal to clientDataHash")
	}

	// The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
	if nil != decoded.SoftwareEnforced.AllApplications || nil != decoded.TeeEnforced.AllApplications {
		return "", nil, ErrAttestationFormat.WithDetails("Attestation certificate extensions contains all applications field")
	}

	// For the following, use only the teeEnforced authorization list if the RP wants to accept only keys from a trusted execution environment, otherwise use the union of teeEnforced and softwareEnforced.
	// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED (which == 0).
	if decoded.SoftwareEnforced.Origin != KM_ORIGIN_GENERATED || decoded.TeeEnforced.Origin != KM_ORIGIN_GENERATED {
		return "", nil, ErrAttestationFormat.WithDetails("Attestation certificate extensions contains authorization list with origin not equal KM_ORIGIN_GENERATED")
	}

	// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN (which == 2).
	if !contains(decoded.SoftwareEnforced.Purpose, KM_PURPOSE_SIGN) && !contains(decoded.TeeEnforced.Purpose, KM_PURPOSE_SIGN) {
		return "", nil, ErrAttestationFormat.WithDetails("Attestation certificate extensions contains authorization list with purpose not equal KM_PURPOSE_SIGN")
	}

	return string(metadata.BasicFull), x5c, err
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}

	return false
}

type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         authorizationList
	TeeEnforced              authorizationList
}

type authorizationList struct {
	Purpose                     []int       `asn1:"tag:1,explicit,set,optional"`
	Algorithm                   int         `asn1:"tag:2,explicit,optional"`
	KeySize                     int         `asn1:"tag:3,explicit,optional"`
	Digest                      []int       `asn1:"tag:5,explicit,set,optional"`
	Padding                     []int       `asn1:"tag:6,explicit,set,optional"`
	EcCurve                     int         `asn1:"tag:10,explicit,optional"`
	RsaPublicExponent           int         `asn1:"tag:200,explicit,optional"`
	RollbackResistance          any         `asn1:"tag:303,explicit,optional"`
	ActiveDateTime              int         `asn1:"tag:400,explicit,optional"`
	OriginationExpireDateTime   int         `asn1:"tag:401,explicit,optional"`
	UsageExpireDateTime         int         `asn1:"tag:402,explicit,optional"`
	NoAuthRequired              any         `asn1:"tag:503,explicit,optional"`
	UserAuthType                int         `asn1:"tag:504,explicit,optional"`
	AuthTimeout                 int         `asn1:"tag:505,explicit,optional"`
	AllowWhileOnBody            any         `asn1:"tag:506,explicit,optional"`
	TrustedUserPresenceRequired any         `asn1:"tag:507,explicit,optional"`
	TrustedConfirmationRequired any         `asn1:"tag:508,explicit,optional"`
	UnlockedDeviceRequired      any         `asn1:"tag:509,explicit,optional"`
	AllApplications             any         `asn1:"tag:600,explicit,optional"`
	ApplicationID               any         `asn1:"tag:601,explicit,optional"`
	CreationDateTime            int         `asn1:"tag:701,explicit,optional"`
	Origin                      int         `asn1:"tag:702,explicit,optional"`
	RootOfTrust                 rootOfTrust `asn1:"tag:704,explicit,optional"`
	OsVersion                   int         `asn1:"tag:705,explicit,optional"`
	OsPatchLevel                int         `asn1:"tag:706,explicit,optional"`
	AttestationApplicationID    []byte      `asn1:"tag:709,explicit,optional"`
	AttestationIDBrand          []byte      `asn1:"tag:710,explicit,optional"`
	AttestationIDDevice         []byte      `asn1:"tag:711,explicit,optional"`
	AttestationIDProduct        []byte      `asn1:"tag:712,explicit,optional"`
	AttestationIDSerial         []byte      `asn1:"tag:713,explicit,optional"`
	AttestationIDImei           []byte      `asn1:"tag:714,explicit,optional"`
	AttestationIDMeid           []byte      `asn1:"tag:715,explicit,optional"`
	AttestationIDManufacturer   []byte      `asn1:"tag:716,explicit,optional"`
	AttestationIDModel          []byte      `asn1:"tag:717,explicit,optional"`
	VendorPatchLevel            int         `asn1:"tag:718,explicit,optional"`
	BootPatchLevel              int         `asn1:"tag:719,explicit,optional"`
}

type rootOfTrust struct {
	verifiedBootKey   []byte            //nolint:unused
	deviceLocked      bool              //nolint:unused
	verifiedBootState verifiedBootState //nolint:unused
	verifiedBootHash  []byte            //nolint:unused
}

type verifiedBootState int

const (
	Verified verifiedBootState = iota
	SelfSigned
	Unverified
	Failed
)

/**
 * The origin of a key (or pair), i.e. where it was generated.  Note that KM_TAG_ORIGIN can be found
 * in either the hardware-enforced or software-enforced list for a key, indicating whether the key
 * is hardware or software-based.  Specifically, a key with KM_ORIGIN_GENERATED in the
 * hardware-enforced list is guaranteed never to have existed outide the secure hardware.
 */
type KM_KEY_ORIGIN int

const (
	KM_ORIGIN_GENERATED = iota /* Generated in keymaster.  Should not exist outside the TEE. */
	KM_ORIGIN_DERIVED          /* Derived inside keymaster.  Likely exists off-device. */
	KM_ORIGIN_IMPORTED         /* Imported into keymaster.  Existed as clear text in Android. */
	KM_ORIGIN_UNKNOWN          /* Keymaster did not record origin.  This value can only be seen on
	 * keys in a keymaster0 implementation.  The keymaster0 adapter uses
	 * this value to document the fact that it is unknown whether the key
	 * was generated inside or imported into keymaster. */
)

/**
 * Possible purposes of a key (or pair).
 */
type KM_PURPOSE int

const (
	KM_PURPOSE_ENCRYPT    = iota /* Usable with RSA, EC and AES keys. */
	KM_PURPOSE_DECRYPT           /* Usable with RSA, EC and AES keys. */
	KM_PURPOSE_SIGN              /* Usable with RSA, EC and HMAC keys. */
	KM_PURPOSE_VERIFY            /* Usable with RSA, EC and HMAC keys. */
	KM_PURPOSE_DERIVE_KEY        /* Usable with EC keys. */
	KM_PURPOSE_WRAP              /* Usable with wrapped keys. */
)

var (
	attAndroidKeyHardwareRootsCertPool *x509.CertPool

	/*
		Google Hardware Attestation Root 3 and Root 4 in raw DER form.

		Source: https://developer.android.com/training/articles/security-key-attestation#root_certificate
		Valid Until:
			Root 3: 2036-11-13
			Root 4: 2042-03-15
		SHA256 Fingerprints:
			Root 3: AB:66:41:17:8A:36:E1:79:AA:0C:1C:DD:DF:9A:16:EB:45:FA:20:94:3E:2B:8C:D7:C7:C0:5C:26:CF:8B:48:7A
			Root 4: CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC
	*/
	attAndroidKeyHardwareRoot3 = []byte{48, 130, 5, 28, 48, 130, 3, 4, 160, 3, 2, 1, 2, 2, 9, 0, 195, 107, 124, 68, 185, 174, 24, 49, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 27, 49, 25, 48, 23, 6, 3, 85, 4, 5, 19, 16, 102, 57, 50, 48, 48, 57, 101, 56, 53, 51, 98, 54, 98, 48, 52, 53, 48, 30, 23, 13, 50, 49, 49, 49, 49, 55, 50, 51, 49, 48, 52, 50, 90, 23, 13, 51, 54, 49, 49, 49, 51, 50, 51, 49, 48, 52, 50, 90, 48, 27, 49, 25, 48, 23, 6, 3, 85, 4, 5, 19, 16, 102, 57, 50, 48, 48, 57, 101, 56, 53, 51, 98, 54, 98, 48, 52, 53, 48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0, 175, 182, 199, 130, 43, 177, 167, 1, 236, 43, 180, 46, 139, 204, 84, 22, 99, 171, 239, 152, 47, 50, 199, 127, 117, 49, 3, 12, 151, 82, 75, 27, 95, 232, 9, 251, 199, 42, 169, 69, 31, 116, 60, 189, 154, 111, 19, 53, 116, 74, 165, 94, 119, 246, 182, 172, 53, 53, 238, 23, 194, 94, 99, 149, 23, 221, 156, 146, 230, 55, 74, 83, 203, 254, 37, 143, 143, 251, 182, 253, 18, 147, 120, 162, 42, 76, 169, 156, 69, 45, 71, 165, 159, 50, 1, 244, 65, 151, 202, 28, 205, 126, 118, 47, 178, 245, 49, 81, 182, 254, 178, 255, 253, 43, 111, 228, 254, 91, 198, 189, 158, 195, 75, 254, 8, 35, 157, 170, 252, 235, 142, 181, 168, 237, 43, 58, 205, 156, 94, 58, 119, 144, 225, 181, 20, 66, 121, 49, 89, 133, 152, 17, 173, 158, 178, 169, 107, 189, 215, 165, 124, 147, 169, 28, 65, 252, 205, 39, 214, 127, 214, 246, 113, 170, 11, 129, 82, 97, 173, 56, 79, 163, 121, 68, 134, 70, 4, 221, 179, 216, 196, 249, 32, 161, 155, 22, 86, 194, 241, 74, 214, 208, 60, 86, 236, 6, 8, 153, 4, 28, 30, 209, 165, 254, 109, 52, 64, 181, 86, 186, 209, 208, 161, 82, 88, 156, 83, 229, 93, 55, 7, 98, 240, 18, 46, 239, 145, 134, 27, 27, 14, 108, 76, 128, 146, 116, 153, 192, 233, 190, 192, 184, 62, 59, 193, 249, 60, 114, 192, 73, 96, 75, 189, 47, 19, 69, 230, 44, 63, 142, 38, 219, 236, 6, 201, 71, 102, 243, 193, 40, 35, 157, 79, 67, 18, 250, 216, 18, 56, 135, 224, 107, 236, 245, 103, 88, 59, 248, 53, 90, 129, 254, 234, 186, 249, 154, 131, 200, 223, 62, 42, 50, 42, 252, 103, 43, 241, 32, 177, 53, 21, 139, 104, 33, 206, 175, 48, 155, 110, 238, 119, 249, 136, 51, 176, 24, 218, 161, 14, 69, 31, 6, 163, 116, 213, 7, 129, 243, 89, 8, 41, 102, 187, 119, 139, 147, 8, 148, 38, 152, 231, 78, 11, 205, 36, 98, 138, 1, 194, 204, 3, 229, 31, 11, 62, 91, 74, 193, 228, 223, 158, 175, 159, 246, 164, 146, 167, 124, 20, 131, 136, 40, 133, 1, 91, 66, 44, 230, 123, 128, 184, 140, 155, 72, 225, 59, 96, 122, 181, 69, 199, 35, 255, 140, 68, 248, 242, 211, 104, 185, 246, 82, 13, 49, 20, 94, 191, 158, 134, 42, 215, 29, 246, 163, 191, 210, 69, 9, 89, 214, 83, 116, 13, 151, 161, 47, 54, 139, 19, 239, 102, 213, 208, 165, 74, 110, 47, 93, 154, 111, 239, 68, 104, 50, 188, 103, 132, 71, 37, 134, 31, 9, 61, 208, 230, 243, 64, 93, 168, 150, 67, 239, 15, 77, 105, 182, 66, 0, 81, 253, 185, 48, 73, 103, 62, 54, 149, 5, 128, 211, 205, 244, 251, 208, 139, 197, 132, 131, 149, 38, 0, 99, 2, 3, 1, 0, 1, 163, 99, 48, 97, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 54, 97, 225, 0, 124, 136, 5, 9, 81, 139, 68, 108, 71, 255, 26, 76, 201, 234, 79, 18, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 54, 97, 225, 0, 124, 136, 5, 9, 81, 139, 68, 108, 71, 255, 26, 76, 201, 234, 79, 18, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 2, 1, 0, 83, 52, 214, 94, 229, 203, 159, 242, 136, 170, 250, 53, 116, 138, 212, 198, 205, 101, 97, 73, 56, 206, 4, 73, 54, 21, 11, 225, 215, 82, 119, 163, 121, 103, 107, 74, 59, 173, 223, 17, 20, 121, 205, 211, 74, 184, 134, 46, 147, 106, 145, 97, 135, 138, 154, 195, 248, 134, 233, 120, 62, 196, 230, 167, 235, 121, 226, 45, 98, 2, 228, 99, 143, 22, 3, 222, 97, 115, 61, 250, 112, 91, 223, 54, 115, 11, 192, 1, 202, 150, 46, 10, 235, 22, 10, 107, 122, 78, 125, 254, 62, 54, 243, 220, 196, 213, 133, 17, 151, 185, 63, 211, 64, 126, 10, 24, 86, 56, 62, 27, 243, 3, 37, 240, 118, 52, 206, 9, 114, 3, 249, 161, 238, 119, 132, 75, 113, 44, 146, 175, 65, 106, 252, 191, 145, 241, 53, 154, 150, 243, 53, 192, 146, 79, 135, 36, 99, 169, 16, 137, 122, 177, 173, 124, 22, 160, 136, 2, 243, 190, 25, 230, 99, 181, 53, 168, 87, 18, 208, 208, 167, 42, 58, 14, 238, 129, 94, 116, 167, 86, 149, 156, 244, 96, 7, 238, 221, 161, 130, 37, 222, 10, 29, 61, 12, 176, 104, 139, 101, 236, 253, 88, 255, 53, 197, 132, 171, 40, 195, 68, 176, 50, 190, 204, 174, 95, 87, 60, 58, 140, 14, 220, 198, 106, 87, 112, 4, 83, 158, 96, 46, 25, 71, 136, 237, 85, 67, 132, 60, 202, 121, 83, 156, 181, 253, 218, 210, 164, 11, 192, 47, 157, 211, 236, 107, 17, 54, 120, 175, 103, 209, 24, 220, 54, 96, 75, 54, 91, 196, 35, 234, 128, 220, 124, 251, 234, 244, 156, 146, 123, 186, 73, 235, 7, 7, 158, 94, 68, 103, 73, 112, 115, 140, 71, 237, 142, 3, 199, 212, 64, 212, 153, 95, 162, 130, 204, 195, 123, 78, 116, 150, 71, 209, 233, 241, 61, 118, 178, 117, 240, 3, 221, 136, 159, 121, 154, 69, 105, 76, 226, 112, 119, 139, 205, 82, 75, 183, 215, 111, 24, 29, 27, 29, 2, 196, 227, 225, 42, 40, 88, 14, 102, 253, 132, 160, 254, 188, 232, 52, 42, 109, 84, 181, 187, 239, 100, 210, 157, 177, 108, 192, 53, 211, 148, 193, 34, 78, 231, 166, 182, 154, 241, 83, 52, 126, 122, 209, 42, 46, 240, 149, 146, 176, 116, 127, 154, 52, 12, 161, 109, 116, 86, 247, 27, 39, 56, 50, 126, 131, 199, 133, 227, 157, 179, 189, 184, 138, 42, 120, 4, 42, 42, 202, 228, 177, 162, 122, 133, 193, 95, 187, 89, 244, 61, 70, 52, 17, 246, 57, 189, 219, 40, 236, 48, 33, 103, 68, 22, 87, 191, 96, 95, 225, 235, 53, 160, 117, 234, 26, 52, 96, 234, 84, 26, 203, 175, 111, 180, 14, 213, 168, 136, 29, 90, 12, 72, 203, 90, 95, 69, 155, 34, 20, 201, 73, 187, 152, 63, 239, 20, 57, 51, 23, 236, 38, 237, 204, 150, 165, 10, 66, 85}
	attAndroidKeyHardwareRoot4 = []byte{48, 130, 5, 28, 48, 130, 3, 4, 160, 3, 2, 1, 2, 2, 9, 0, 241, 193, 114, 166, 153, 234, 245, 29, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 27, 49, 25, 48, 23, 6, 3, 85, 4, 5, 19, 16, 102, 57, 50, 48, 48, 57, 101, 56, 53, 51, 98, 54, 98, 48, 52, 53, 48, 30, 23, 13, 50, 50, 48, 51, 50, 48, 49, 56, 48, 55, 52, 56, 90, 23, 13, 52, 50, 48, 51, 49, 53, 49, 56, 48, 55, 52, 56, 90, 48, 27, 49, 25, 48, 23, 6, 3, 85, 4, 5, 19, 16, 102, 57, 50, 48, 48, 57, 101, 56, 53, 51, 98, 54, 98, 48, 52, 53, 48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0, 175, 182, 199, 130, 43, 177, 167, 1, 236, 43, 180, 46, 139, 204, 84, 22, 99, 171, 239, 152, 47, 50, 199, 127, 117, 49, 3, 12, 151, 82, 75, 27, 95, 232, 9, 251, 199, 42, 169, 69, 31, 116, 60, 189, 154, 111, 19, 53, 116, 74, 165, 94, 119, 246, 182, 172, 53, 53, 238, 23, 194, 94, 99, 149, 23, 221, 156, 146, 230, 55, 74, 83, 203, 254, 37, 143, 143, 251, 182, 253, 18, 147, 120, 162, 42, 76, 169, 156, 69, 45, 71, 165, 159, 50, 1, 244, 65, 151, 202, 28, 205, 126, 118, 47, 178, 245, 49, 81, 182, 254, 178, 255, 253, 43, 111, 228, 254, 91, 198, 189, 158, 195, 75, 254, 8, 35, 157, 170, 252, 235, 142, 181, 168, 237, 43, 58, 205, 156, 94, 58, 119, 144, 225, 181, 20, 66, 121, 49, 89, 133, 152, 17, 173, 158, 178, 169, 107, 189, 215, 165, 124, 147, 169, 28, 65, 252, 205, 39, 214, 127, 214, 246, 113, 170, 11, 129, 82, 97, 173, 56, 79, 163, 121, 68, 134, 70, 4, 221, 179, 216, 196, 249, 32, 161, 155, 22, 86, 194, 241, 74, 214, 208, 60, 86, 236, 6, 8, 153, 4, 28, 30, 209, 165, 254, 109, 52, 64, 181, 86, 186, 209, 208, 161, 82, 88, 156, 83, 229, 93, 55, 7, 98, 240, 18, 46, 239, 145, 134, 27, 27, 14, 108, 76, 128, 146, 116, 153, 192, 233, 190, 192, 184, 62, 59, 193, 249, 60, 114, 192, 73, 96, 75, 189, 47, 19, 69, 230, 44, 63, 142, 38, 219, 236, 6, 201, 71, 102, 243, 193, 40, 35, 157, 79, 67, 18, 250, 216, 18, 56, 135, 224, 107, 236, 245, 103, 88, 59, 248, 53, 90, 129, 254, 234, 186, 249, 154, 131, 200, 223, 62, 42, 50, 42, 252, 103, 43, 241, 32, 177, 53, 21, 139, 104, 33, 206, 175, 48, 155, 110, 238, 119, 249, 136, 51, 176, 24, 218, 161, 14, 69, 31, 6, 163, 116, 213, 7, 129, 243, 89, 8, 41, 102, 187, 119, 139, 147, 8, 148, 38, 152, 231, 78, 11, 205, 36, 98, 138, 1, 194, 204, 3, 229, 31, 11, 62, 91, 74, 193, 228, 223, 158, 175, 159, 246, 164, 146, 167, 124, 20, 131, 136, 40, 133, 1, 91, 66, 44, 230, 123, 128, 184, 140, 155, 72, 225, 59, 96, 122, 181, 69, 199, 35, 255, 140, 68, 248, 242, 211, 104, 185, 246, 82, 13, 49, 20, 94, 191, 158, 134, 42, 215, 29, 246, 163, 191, 210, 69, 9, 89, 214, 83, 116, 13, 151, 161, 47, 54, 139, 19, 239, 102, 213, 208, 165, 74, 110, 47, 93, 154, 111, 239, 68, 104, 50, 188, 103, 132, 71, 37, 134, 31, 9, 61, 208, 230, 243, 64, 93, 168, 150, 67, 239, 15, 77, 105, 182, 66, 0, 81, 253, 185, 48, 73, 103, 62, 54, 149, 5, 128, 211, 205, 244, 251, 208, 139, 197, 132, 131, 149, 38, 0, 99, 2, 3, 1, 0, 1, 163, 99, 48, 97, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 54, 97, 225, 0, 124, 136, 5, 9, 81, 139, 68, 108, 71, 255, 26, 76, 201, 234, 79, 18, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 54, 97, 225, 0, 124, 136, 5, 9, 81, 139, 68, 108, 71, 255, 26, 76, 201, 234, 79, 18, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 2, 1, 0, 124, 112, 202, 147, 150, 81, 220, 241, 79, 170, 10, 179, 165, 131, 113, 251, 215, 190, 37, 153, 160, 172, 110, 143, 219, 39, 64, 181, 236, 145, 32, 48, 182, 248, 146, 250, 234, 177, 118, 108, 211, 85, 55, 152, 31, 234, 0, 24, 63, 214, 222, 79, 119, 144, 14, 68, 112, 17, 179, 88, 97, 168, 98, 2, 91, 249, 202, 49, 171, 249, 239, 135, 253, 173, 147, 120, 60, 45, 153, 150, 231, 198, 93, 190, 236, 33, 210, 105, 26, 35, 189, 114, 212, 97, 136, 187, 152, 186, 92, 181, 208, 151, 28, 81, 145, 132, 30, 145, 210, 96, 205, 134, 182, 72, 24, 109, 150, 218, 234, 91, 2, 61, 128, 0, 63, 205, 220, 200, 53, 126, 213, 163, 164, 77, 253, 81, 10, 159, 229, 51, 67, 202, 190, 108, 88, 55, 93, 17, 98, 194, 186, 223, 88, 235, 149, 225, 157, 113, 217, 49, 161, 34, 191, 254, 100, 144, 110, 7, 22, 158, 96, 4, 102, 188, 199, 160, 93, 127, 210, 11, 40, 212, 118, 96, 34, 125, 24, 47, 53, 97, 45, 32, 63, 137, 112, 151, 225, 4, 246, 135, 114, 121, 207, 124, 231, 150, 226, 134, 214, 123, 252, 53, 7, 113, 122, 45, 131, 32, 136, 64, 73, 103, 238, 243, 78, 2, 3, 222, 156, 64, 164, 211, 149, 166, 158, 217, 252, 30, 169, 120, 221, 55, 95, 239, 218, 122, 142, 134, 120, 13, 203, 61, 119, 235, 89, 133, 154, 190, 23, 153, 162, 135, 252, 139, 83, 192, 231, 187, 216, 210, 61, 101, 204, 18, 214, 85, 90, 10, 251, 8, 145, 48, 194, 17, 119, 102, 246, 176, 141, 60, 6, 53, 210, 36, 238, 156, 129, 197, 93, 24, 126, 236, 163, 243, 148, 113, 158, 192, 42, 191, 241, 51, 168, 132, 20, 103, 211, 243, 77, 126, 30, 238, 70, 201, 78, 73, 159, 241, 41, 179, 125, 180, 192, 109, 195, 126, 217, 241, 221, 175, 190, 117, 234, 253, 133, 157, 178, 109, 126, 36, 181, 112, 159, 172, 152, 15, 252, 154, 112, 210, 65, 151, 10, 93, 118, 86, 188, 121, 165, 76, 142, 193, 122, 156, 25, 200, 129, 3, 159, 247, 50, 146, 123, 78, 167, 73, 58, 175, 131, 5, 7, 162, 200, 14, 16, 38, 73, 103, 81, 46, 205, 177, 248, 202, 204, 27, 183, 77, 173, 42, 210, 132, 22, 28, 126, 191, 227, 147, 129, 239, 244, 233, 95, 163, 26, 202, 147, 88, 187, 31, 172, 224, 141, 46, 224, 60, 31, 239, 179, 250, 149, 4, 54, 106, 106, 158, 113, 232, 189, 162, 56, 238, 0, 190, 76, 218, 100, 129, 129, 164, 144, 20, 250, 7, 249, 191, 83, 77, 65, 184, 224, 65, 79, 56, 72, 148, 193, 25, 171, 218, 164, 13, 107, 140, 217, 192, 57, 145, 110, 85, 220, 82, 84, 113, 241, 231, 195, 82, 29, 96, 136, 54, 91, 24, 59, 200, 119, 16, 101, 233, 133, 66}
)
