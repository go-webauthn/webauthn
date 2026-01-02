package webauthn

import (
	"crypto/sha256"
	"fmt"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
)

// Credential contains all needed information about a WebAuthn credential for storage. This struct is effectively the
// Credential Record as described in the specification.
//
// Providing this data structure is preserved properly this Credential can be properly verified using the
// [Credential.Verify] function when provided a [metadata.Provider].
//
// It is strongly recommended for the best security that a [Credential] is encrypted at rest with the exception of the
// ID and the value you use to lookup the user. This prevents a person with access to the database being able to
// compromise privacy by being able to view this data, as well as prevents them being able to compromise ecurity by
// adding or modifying a Credential without them also having access to the encryption key.
//
// See: §4. Terminology: Credential Record (https://www.w3.org/TR/webauthn-3/#credential-record)
type Credential struct {
	// The ID is the ID of the public key credential source. Described by the Credential Record 'id' field.
	ID []byte `json:"id"`

	// The credential public key of the public key credential source. Described by the Credential Record 'publicKey'
	// field.
	PublicKey []byte `json:"publicKey"`

	// The AttestationType stores the attestation format used (if any) by the authenticator when creating the
	// Credential.
	//
	// Important Note: This field is named attestationType but this is actually the attestation format.
	AttestationType string `json:"attestationType"`

	// Transport types the authenticator supports. Described by the Credential Record 'transports' field.
	Transport []protocol.AuthenticatorTransport `json:"transport"`

	// Flags represent the commonly stored flags.
	Flags CredentialFlags `json:"flags"`

	// The Authenticator information for a given Credential.
	Authenticator Authenticator `json:"authenticator"`

	// The attestation values that can be used to validate this Credential via the MDS3 at a later date.
	Attestation CredentialAttestation `json:"attestation"`
}

// Credentials is a decorator type which allows easily converting a [Credential] slice into a
// [protocol.CredentialDescriptor] slice by utilizing the [Credentials.CredentialDescriptors] method. This will be the
// type used globally for the library in a future release.
type Credentials []Credential

// CredentialDescriptors returns the [protocol.CredentialDescriptor] slice for this [Credentials] type.
func (c Credentials) CredentialDescriptors() (descriptors []protocol.CredentialDescriptor) {
	descriptors = make([]protocol.CredentialDescriptor, len(c))

	for i, credential := range c {
		descriptors[i] = credential.Descriptor()
	}

	return descriptors
}

// NewCredentialFlags is a utility function that is used to derive the [Credential]'s Flags field given a
// [protocol.AuthenticatorFlags]. This allows implementers to solely save the Raw field of the [CredentialFlags] to
// restore them appropriately for appropriate processing without concern that changes forced upon implementers by the
// W3C will introduce breaking changes.
func NewCredentialFlags(flags protocol.AuthenticatorFlags) CredentialFlags {
	return CredentialFlags{
		UserPresent:    flags.HasUserPresent(),
		UserVerified:   flags.HasUserVerified(),
		BackupEligible: flags.HasBackupEligible(),
		BackupState:    flags.HasBackupState(),
		raw:            flags,
	}
}

// CredentialFlags is a JSON representation of the flags.
type CredentialFlags struct {
	// Flag UP indicates the users presence.
	UserPresent bool `json:"userPresent"`

	// Flag UV indicates the user performed verification.
	UserVerified bool `json:"userVerified"`

	// Flag BE indicates the credential is able to be backed up and/or sync'd between devices. This should NEVER change.
	BackupEligible bool `json:"backupEligible"`

	// Flag BS indicates the credential has been backed up and/or sync'd. This value can change but it's recommended
	// that RP's keep track of this value.
	BackupState bool `json:"backupState"`

	raw protocol.AuthenticatorFlags
}

// ProtocolValue returns the underlying [protocol.AuthenticatorFlags] provided this [CredentialFlags] was created using
// NewCredentialFlags.
func (f CredentialFlags) ProtocolValue() protocol.AuthenticatorFlags {
	return f.raw
}

// CredentialAttestation is a decoded representation of the [protocol.AuthenticatorAttestationResponse] in a format that
// can easily be serialized.
type CredentialAttestation struct {
	ClientDataJSON     []byte `json:"clientDataJSON"`
	ClientDataHash     []byte `json:"clientDataHash"`
	AuthenticatorData  []byte `json:"authenticatorData"`
	PublicKeyAlgorithm int64  `json:"publicKeyAlgorithm"`
	Object             []byte `json:"object"`
}

// Descriptor converts a [Credential] into a [protocol.CredentialDescriptor].
func (c Credential) Descriptor() (descriptor protocol.CredentialDescriptor) {
	return protocol.CredentialDescriptor{
		Type:            protocol.PublicKeyCredentialType,
		CredentialID:    c.ID,
		Transport:       c.Transport,
		AttestationType: c.AttestationType,
	}
}

// NewCredential will return a credential pointer on successful validation of a registration response.
func NewCredential(clientDataHash []byte, c *protocol.ParsedCredentialCreationData) (credential *Credential, err error) {
	credential = &Credential{
		ID:              c.Response.AttestationObject.AuthData.AttData.CredentialID,
		PublicKey:       c.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
		AttestationType: c.Response.AttestationObject.Format,
		Transport:       c.Response.Transports,
		Flags:           NewCredentialFlags(c.Response.AttestationObject.AuthData.Flags),
		Authenticator: Authenticator{
			AAGUID:     c.Response.AttestationObject.AuthData.AttData.AAGUID,
			SignCount:  c.Response.AttestationObject.AuthData.Counter,
			Attachment: c.AuthenticatorAttachment,
		},
		Attestation: CredentialAttestation{
			ClientDataJSON:     c.Raw.AttestationResponse.ClientDataJSON,
			ClientDataHash:     clientDataHash,
			AuthenticatorData:  c.Raw.AttestationResponse.AuthenticatorData,
			PublicKeyAlgorithm: c.Raw.AttestationResponse.PublicKeyAlgorithm,
			Object:             c.Raw.AttestationResponse.AttestationObject,
		},
	}

	return credential, nil
}

// Verify this credentials against the metadata.Provider given.
func (c Credential) Verify(mds metadata.Provider) (err error) {
	if mds == nil {
		return fmt.Errorf("error verifying credential: the metadata provider must be provided but it's nil")
	}

	raw := &protocol.AuthenticatorAttestationResponse{
		AuthenticatorResponse: protocol.AuthenticatorResponse{
			ClientDataJSON: c.Attestation.ClientDataJSON,
		},
		Transports:         make([]string, len(c.Transport)),
		AuthenticatorData:  c.Attestation.AuthenticatorData,
		PublicKey:          c.PublicKey,
		PublicKeyAlgorithm: c.Attestation.PublicKeyAlgorithm,
		AttestationObject:  c.Attestation.Object,
	}

	for i, transport := range c.Transport {
		raw.Transports[i] = string(transport)
	}

	var attestation *protocol.ParsedAttestationResponse

	if attestation, err = raw.Parse(); err != nil {
		return fmt.Errorf("error verifying credential: error parsing attestation: %w", err)
	}

	clientDataHash := c.Attestation.ClientDataHash

	if len(clientDataHash) == 0 {
		sum := sha256.Sum256(c.Attestation.ClientDataJSON)

		clientDataHash = sum[:]
	}

	if err = attestation.AttestationObject.VerifyAttestation(clientDataHash, mds); err != nil {
		return fmt.Errorf("error verifying credential: error verifying attestation: %w", err)
	}

	return nil
}
