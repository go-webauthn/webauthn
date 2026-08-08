package protocol

import (
	"encoding/asn1"
)

type androidkeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         androidkeyAuthorizationList
	TeeEnforced              androidkeyAuthorizationList
}

// androidkeyDescriptionRaw mirrors [keyDescription] but captures the two authorization lists as raw elements, so the elements
// they carry can be examined before [authorizationList] decoding discards those it can't model. The leading members
// must remain identical to those of [keyDescription].
type androidkeyDescriptionRaw struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

// androidkeyAuthorizationList is the Keymaster/KeyMint AuthorizationList, whose schema §8.4.1 defers to normatively.
//
// Every tag in the schema must be modelled even when the verification procedure never reads it. encoding/asn1 matches
// the fields of a struct against the elements of a sequence in order, and on meeting an element which matches no
// remaining field it abandons every field that follows, leaving them at their zero value with no error. An unmodelled
// tag which is absent here therefore erases the fields declared after it, so the members which exist only to occupy
// their position must not be removed. Those are declared as [asn1.RawValue] as it imposes no expectation on the
// content, so a value which is absent, of an unexpected type, or too large for its Go type can't fail the decode of a
// list which is otherwise sound.
//
// See: https://source.android.com/docs/security/features/keystore/attestation
type androidkeyAuthorizationList struct {
	Purpose                     []int                 `asn1:"tag:1,explicit,set,optional"`
	Algorithm                   int                   `asn1:"tag:2,explicit,optional"`
	KeySize                     int                   `asn1:"tag:3,explicit,optional"`
	BlockMode                   asn1.RawValue         `asn1:"tag:4,explicit,optional"`
	Digest                      []int                 `asn1:"tag:5,explicit,set,optional"`
	Padding                     []int                 `asn1:"tag:6,explicit,set,optional"`
	CallerNonce                 asn1.RawValue         `asn1:"tag:7,explicit,optional"`
	MinMacLength                asn1.RawValue         `asn1:"tag:8,explicit,optional"`
	EcCurve                     int                   `asn1:"tag:10,explicit,optional"`
	MlDsaVariant                asn1.RawValue         `asn1:"tag:11,explicit,optional"`
	RsaPublicExponent           int                   `asn1:"tag:200,explicit,optional"`
	MgfDigest                   asn1.RawValue         `asn1:"tag:203,explicit,optional"`
	RollbackResistance          asn1.RawValue         `asn1:"tag:303,explicit,optional"`
	EarlyBootOnly               asn1.RawValue         `asn1:"tag:305,explicit,optional"`
	ActiveDateTime              int                   `asn1:"tag:400,explicit,optional"`
	OriginationExpireDateTime   int                   `asn1:"tag:401,explicit,optional"`
	UsageExpireDateTime         int                   `asn1:"tag:402,explicit,optional"`
	UsageCountLimit             asn1.RawValue         `asn1:"tag:405,explicit,optional"`
	UserSecureID                asn1.RawValue         `asn1:"tag:502,explicit,optional"`
	NoAuthRequired              asn1.RawValue         `asn1:"tag:503,explicit,optional"`
	UserAuthType                int                   `asn1:"tag:504,explicit,optional"`
	AuthTimeout                 int                   `asn1:"tag:505,explicit,optional"`
	AllowWhileOnBody            asn1.RawValue         `asn1:"tag:506,explicit,optional"`
	TrustedUserPresenceRequired asn1.RawValue         `asn1:"tag:507,explicit,optional"`
	TrustedConfirmationRequired asn1.RawValue         `asn1:"tag:508,explicit,optional"`
	UnlockedDeviceRequired      asn1.RawValue         `asn1:"tag:509,explicit,optional"`
	AllApplications             asn1.RawValue         `asn1:"tag:600,explicit,optional"`
	ApplicationID               asn1.RawValue         `asn1:"tag:601,explicit,optional"`
	CreationDateTime            int                   `asn1:"tag:701,explicit,optional"`
	Origin                      asn1.RawValue         `asn1:"tag:702,explicit,optional"`
	RootOfTrust                 androidkeyRootOfTrust `asn1:"tag:704,explicit,optional"`
	OsVersion                   int                   `asn1:"tag:705,explicit,optional"`
	OsPatchLevel                int                   `asn1:"tag:706,explicit,optional"`
	AttestationApplicationID    []byte                `asn1:"tag:709,explicit,optional"`
	AttestationIDBrand          []byte                `asn1:"tag:710,explicit,optional"`
	AttestationIDDevice         []byte                `asn1:"tag:711,explicit,optional"`
	AttestationIDProduct        []byte                `asn1:"tag:712,explicit,optional"`
	AttestationIDSerial         []byte                `asn1:"tag:713,explicit,optional"`
	AttestationIDImei           []byte                `asn1:"tag:714,explicit,optional"`
	AttestationIDMeid           []byte                `asn1:"tag:715,explicit,optional"`
	AttestationIDManufacturer   []byte                `asn1:"tag:716,explicit,optional"`
	AttestationIDModel          []byte                `asn1:"tag:717,explicit,optional"`
	VendorPatchLevel            int                   `asn1:"tag:718,explicit,optional"`
	BootPatchLevel              int                   `asn1:"tag:719,explicit,optional"`
	DeviceUniqueAttestation     asn1.RawValue         `asn1:"tag:720,explicit,optional"`
	AttestationIDSecondImei     asn1.RawValue         `asn1:"tag:723,explicit,optional"`
	ModuleHash                  asn1.RawValue         `asn1:"tag:724,explicit,optional"`
}

type androidkeyRootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

type verifiedBootState int

const (
	Verified verifiedBootState = iota
	SelfSigned
	Unverified
	Failed
)

const (
	// KM_ORIGIN_GENERATED means generated in keymaster. Should not exist outside the TEE.
	KM_ORIGIN_GENERATED = iota

	// KM_ORIGIN_DERIVED means derived inside keymaster. Likely exists off-device.
	KM_ORIGIN_DERIVED

	// KM_ORIGIN_IMPORTED means imported into keymaster. Existed as clear text in Android.
	KM_ORIGIN_IMPORTED

	// KM_ORIGIN_UNKNOWN means keymaster did not record origin.  This value can only be seen on keys in a keymaster0
	// implementation. The keymaster0 adapter uses this value to document the fact that it is unknown whether the key
	// was generated inside or imported into keymaster.
	KM_ORIGIN_UNKNOWN
)

const (
	// KM_PURPOSE_ENCRYPT is usable with RSA, EC and AES keys.
	KM_PURPOSE_ENCRYPT = iota

	// KM_PURPOSE_DECRYPT is usable with RSA, EC and AES keys.
	KM_PURPOSE_DECRYPT

	// KM_PURPOSE_SIGN is usable with RSA, EC and HMAC keys.
	KM_PURPOSE_SIGN

	// KM_PURPOSE_VERIFY is usable with RSA, EC and HMAC keys.
	KM_PURPOSE_VERIFY

	// KM_PURPOSE_DERIVE_KEY is usable with EC keys.
	KM_PURPOSE_DERIVE_KEY

	// KM_PURPOSE_WRAP is usable with wrapped keys.
	KM_PURPOSE_WRAP
)
