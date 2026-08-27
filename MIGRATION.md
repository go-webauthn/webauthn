# Migration Guide

This document describes the changes between releases which require significant manual intervention, and how to make them.
It covers changes that break the build, changes that build cleanly but behave differently, changes affecting data you
have already stored, and the deprecations that will become breaking changes in a future release.

Only the notable changes are listed. For the complete set see the
[CHANGELOG](CHANGELOG.md) and the release notes.

---

## v0.17.4 → v0.18.0

Two changes account for most of the work in this release. The decisions the specification delegates to the Relying
Party became explicit parameters instead of implicit defaults, and the extensions became typed instead of
`map[string]any`. Most integrations will be touched by [§1.1](#11-extension-inputs-and-outputs-are-typed) and
[§1.2](#12-registrationoption-and-loginoption-return-an-error) and by nothing else.

Read [§2](#2-it-builds-but-behaves-differently) even if your build is clean. Several changes tighten validation
without changing a signature, and one of them will reject a configuration that worked before.

### How to use this guide

1. Upgrade the module and run `go build ./...`. Work through [§1](#1-it-no-longer-builds) for each error.
2. Read [§2](#2-it-builds-but-behaves-differently) and check your configuration against it.
3. If you serialize credentials or session data yourself, read [§3](#3-stored-data).
4. Read [§4](#4-configuration) for the new fields, and [§5](#5-deprecations) before your next upgrade.

### Summary

| Symbol                                                 | Change                                                           | Section                                                       |
|--------------------------------------------------------|------------------------------------------------------------------|---------------------------------------------------------------|
| `protocol.AuthenticationExtensions`                    | `map[string]any` → struct                                        | [1.1](#11-extension-inputs-and-outputs-are-typed)             |
| `protocol.AuthenticationExtensionsClientOutputs`       | `map[string]any` → struct                                        | [1.1](#11-extension-inputs-and-outputs-are-typed)             |
| `protocol.Extensions`                                  | Removed                                                          | [1.1](#11-extension-inputs-and-outputs-are-typed)             |
| `webauthn.SessionData.Extensions`                      | Now `protocol.SessionExtensions`                                 | [1.1](#11-extension-inputs-and-outputs-are-typed)             |
| `webauthn.WithExtensions`                              | Now variadic `...ExtensionOption`                                | [1.1](#11-extension-inputs-and-outputs-are-typed)             |
| `webauthn.WithAssertionExtensions`                     | Now variadic `...ExtensionOption`                                | [1.1](#11-extension-inputs-and-outputs-are-typed)             |
| `protocol.ParsedPublicKeyCredential.GetAppID`          | Takes `SessionExtensions`                                        | [1.1](#11-extension-inputs-and-outputs-are-typed)             |
| `webauthn.RegistrationOption`                          | Now returns `error`                                              | [1.2](#12-registrationoption-and-loginoption-return-an-error) |
| `webauthn.LoginOption`                                 | Now returns `error`                                              | [1.2](#12-registrationoption-and-loginoption-return-an-error) |
| `protocol.CollectedClientData.Verify`                  | Gained `rpOpaqueOrigins`                                         | [1.3](#13-verification-functions-take-policy-arguments)       |
| `protocol.ParsedCredentialCreationData.Verify`         | Gained `rpOpaqueOrigins`, `AttestationPolicy`, `SignaturePolicy` | [1.3](#13-verification-functions-take-policy-arguments)       |
| `protocol.ParsedCredentialAssertionData.Verify`        | Gained `rpOpaqueOrigins`, `SignaturePolicy`                      | [1.3](#13-verification-functions-take-policy-arguments)       |
| `protocol.AttestationObject.Verify`                    | Gained `AttestationPolicy`, `SignaturePolicy`                    | [1.3](#13-verification-functions-take-policy-arguments)       |
| `protocol.AttestationObject.VerifyAttestation`         | Gained `AttestationPolicy`, `SignaturePolicy`                    | [1.3](#13-verification-functions-take-policy-arguments)       |
| `webauthn.Credential.Verify`                           | Gained `AttestationPolicy`, `SignaturePolicy`                    | [1.3](#13-verification-functions-take-policy-arguments)       |
| `webauthn.Credential.VerifyAttestationType`            | Gained `AttestationPolicy`, `SignaturePolicy`                    | [1.3](#13-verification-functions-take-policy-arguments)       |
| `protocol.RegisterAttestationFormat`                   | Handler signature gained both policies                           | [1.3](#13-verification-functions-take-policy-arguments)       |
| `webauthncose.HasherFromCOSEAlg`                       | Returns `(hash.Hash, bool)`                                      | [1.4](#14-protocolwebauthncose)                               |
| `webauthncose.COSESignatureAlgorithmDetails`           | Value type is now named                                          | [1.4](#14-protocolwebauthncose)                               |
| `webauthncose.SetExperimentalInsecureAllowBERIntegers` | Removed                                                          | [1.4](#14-protocolwebauthncose)                               |
| `metadata.StatusReport.EffectiveDate`                  | `time.Time` → `*time.Time`                                       | [1.5](#15-metadata)                                           |
| `metadata.BiometricStatusReport.EffectiveDate`         | `time.Time` → `*time.Time`                                       | [1.5](#15-metadata)                                           |
| `metadata.Statement.CredentialExportProtocolConfigURL` | Renamed `CredentialExchangeConfigURL`                            | [1.5](#15-metadata)                                           |
| `metadata.ProductionMDSRoot`                           | New root certificate                                             | [2.6](#26-the-mds-root-certificate-was-replaced)              |
| `webauthn.ConfigProvider`                              | Three new methods                                                | [1.6](#16-webauthnconfigprovider)                             |

---

## 1. It no longer builds

### 1.1 Extension inputs and outputs are typed

`protocol.AuthenticationExtensions` and `protocol.AuthenticationExtensionsClientOutputs` were
`map[string]any`. Both are now structs with a field per extension defined in §10 of the specification, so an
extension name is checked at compile time, values carry their real type, and an output that was never requested
can be detected. `protocol.Extensions` (an alias for `any` that nothing consumed) was removed.

#### Requesting extensions

Extensions are now requested with option functions rather than by building a map. `WithExtensions` and
`WithAssertionExtensions` still exist, but they take `...webauthn.ExtensionOption` instead of a map.

Before:

```go
options, session, err := w.BeginRegistration(user, webauthn.WithExtensions(protocol.AuthenticationExtensions{
	"credProps":    true,
	"minPinLength": true,
}))
```

After:

```go
options, session, err := w.BeginRegistration(user, webauthn.WithExtensions(
	webauthn.WithExtensionCredProps(),
	webauthn.WithExtensionMinPinLength(),
))
```

Before:

```go
options, session, err := w.BeginLogin(user, webauthn.WithAssertionExtensions(protocol.AuthenticationExtensions{
	"appid": "https://example.com/appid.json",
}))
```

After:

```go
options, session, err := w.BeginLogin(user, webauthn.WithAssertionExtensions(
	webauthn.WithExtensionAppID("https://example.com/appid.json"),
))
```

Each option knows which ceremony its extension applies to, so requesting a registration-only extension during
authentication is now an error returned from `BeginLogin` rather than an input the client silently ignores.

The full set:

| Ceremony       | Option                                                                                                   |
|----------------|----------------------------------------------------------------------------------------------------------|
| Registration   | `WithExtensionCredProps()`                                                                               |
| Registration   | `WithExtensionMinPinLength()`                                                                            |
| Registration   | `WithExtensionAppIDExclude(appid string)`                                                                |
| Registration   | `WithExtensionCredBlob(blob []byte)`                                                                     |
| Registration   | `WithExtensionHMACCreateSecret()`                                                                        |
| Registration   | `WithExtensionCredentialProtectionPolicy(policy protocol.CredentialProtectionPolicy, enforce bool)`      |
| Registration   | `WithExtensionLargeBlobSupport(support protocol.LargeBlobSupport)`                                       |
| Authentication | `WithExtensionAppID(appid string)`                                                                       |
| Authentication | `WithExtensionGetCredBlob()`                                                                             |
| Authentication | `WithExtensionHMACGetSecret(salt1, salt2 []byte)`                                                        |
| Authentication | `WithExtensionLargeBlobRead()`                                                                           |
| Authentication | `WithExtensionLargeBlobWrite(blob []byte)`                                                               |
| Authentication | `WithExtensionPRFByCredential(byCredential map[string]protocol.PRFValues, fallback *protocol.PRFValues)` |
| Both           | `WithExtensionPRFSupport()`                                                                              |
| Both           | `WithExtensionPRF(eval protocol.PRFValues)`                                                              |
| Both           | `WithExtensionUVM()`                                                                                     |
| Both           | `WithExtensionRemoteClientDataJSON(clientDataJSON string)`                                               |

#### Extensions this library does not model

Two escape hatches exist, and they do different things.

`WithExtension(name string, value any)` sets a single extension this library does not model. The value is placed in
the `Extra` field of `AuthenticationExtensions` and conveyed to the client verbatim.

`WithExtensionInputs(in protocol.AuthenticationExtensions)` replaces the entire inputs structure, discarding
anything earlier options set. Its typed fields are serialized as the members they model, exactly as the dedicated
options produce; only the members of its own `Extra` map are carried through verbatim.

```go
options, session, err := w.BeginRegistration(user, webauthn.WithExtensions(
	webauthn.WithExtension("example.myExtension", map[string]any{"enabled": true}),
))
```

`WithExtension` rejects an identifier this library does model, and names the dedicated option instead. The
comparison is case-insensitive.

If you hold extension inputs as a map already, say from a configuration file,
`protocol.ParseAuthenticationExtensions(in map[string]any) (protocol.AuthenticationExtensions, error)` converts
one, binding the modelled members and collecting the rest into `Extra`:

```go
in, err := protocol.ParseAuthenticationExtensions(fromConfig)
if err != nil {
	return err
}

options, session, err := w.BeginRegistration(user, webauthn.WithExtensions(webauthn.WithExtensionInputs(in)))
```

#### Reading extension outputs

`ClientExtensionResults` is a struct. Every modelled member is a pointer, so an absent output is distinguishable
from a `false` one.

Before:

```go
if rk, ok := parsedResponse.ClientExtensionResults["credProps"].(map[string]any)["rk"].(bool); ok && rk {
	// Discoverable.
}
```

After:

```go
if props := parsedResponse.ClientExtensionResults.CredProps; props != nil && props.RK != nil && *props.RK {
	// Discoverable.
}
```

Unmodelled outputs are in `ClientExtensionResults.Extra`, keyed as before.

For the durable results of a registration, prefer `webauthn.Credential.Extensions`; see
[§3.1](#31-webauthncredential-gained-an-extensions-field).

#### `webauthn.SessionData.Extensions`

`SessionData.Extensions` is now `protocol.SessionExtensions` rather than `protocol.AuthenticationExtensions`. It
holds only what the finish step needs in order to verify the outputs: the list of requested extension identifiers,
the AppID values, and the flags that later assertions are checked against. The PRF salts and any large blob write
payload are deliberately excluded, because they are secrets or bulk with no verification role.

Nothing in your code needs to populate it; `BeginRegistration` and `BeginLogin` do that. Its serialized form has
changed though, so see [§3.2](#32-sessions-in-flight-across-the-upgrade).

If you call `protocol.ParsedPublicKeyCredential.GetAppID` directly, it now takes the `SessionExtensions` value
rather than the raw inputs:

```go
appID, err := parsedResponse.GetAppID(session.Extensions, credential.AttestationFormat)
```

### 1.2 `RegistrationOption` and `LoginOption` return an error

Both option types now return an `error`, so an option can reject its own input at the point the ceremony begins
rather than producing an options object the client rejects later.

Before:

```go
func WithMyPolicy() webauthn.RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Attestation = protocol.PreferDirectAttestation
	}
}
```

After:

```go
func WithMyPolicy() webauthn.RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.Attestation = protocol.PreferDirectAttestation

		return nil
	}
}
```

The same change applies to `webauthn.LoginOption`, whose argument remains
`*protocol.PublicKeyCredentialRequestOptions`. Options supplied by this library are unaffected at the call site;
only custom options need editing.

### 1.3 Verification functions take policy arguments

Two things §8 and §7 delegate to the Relying Party are now explicit parameters rather than fixed behavior:
`protocol.AttestationPolicy` (the Android Key authorization scope, and how many sub-statements of a compound
attestation must verify) and `protocol.SignaturePolicy` (which ASN.1 encodings an ECDSA signature may use). Both
zero values select the behavior the specification requires, so passing the zero value everywhere preserves the
previous conforming behavior, with the one exception noted in [§1.4](#14-protocolwebauthncose) for anyone who had
opted into BER integers.

Separately, an `rpOpaqueOrigins` parameter was added immediately after `rpOrigins`; see
[§2.2](#22-opaque-origins-have-their-own-configuration-field). Pass `nil` to accept no opaque origins.

If you drive the `webauthn` package (`BeginRegistration`/`CreateCredential`, `BeginLogin`/`ValidateLogin`), none
of this reaches you: `webauthn.Config` carries the policies and passes them down. These signatures matter to
callers of the `protocol` package directly.

| Function                                       | New parameters                                                                                                 |
|------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| `(*CollectedClientData).Verify`                | `rpOpaqueOrigins []string` after `rpOrigins`                                                                   |
| `(*ParsedCredentialCreationData).Verify`       | `rpOpaqueOrigins []string` after `rpOrigins`; `policy AttestationPolicy, signature SignaturePolicy` at the end |
| `(*ParsedCredentialAssertionData).Verify`      | `rpOpaqueOrigins []string` after `rpOrigins`; `signature SignaturePolicy` at the end                           |
| `(*AttestationObject).Verify`                  | `policy AttestationPolicy, signature SignaturePolicy` at the end                                               |
| `(*AttestationObject).VerifyAttestation`       | `policy AttestationPolicy, signature SignaturePolicy` at the end                                               |
| `(*webauthn.Credential).Verify`                | `policy protocol.AttestationPolicy, signature protocol.SignaturePolicy` at the end                             |
| `(*webauthn.Credential).VerifyAttestationType` | `policy protocol.AttestationPolicy, signature protocol.SignaturePolicy`                                        |

Before:

```go
err := credential.Verify(mds)
```

After, taking the policies from the configuration you already have:

```go
err := credential.Verify(mds, config.Attestation, config.Signature)
```

Or, where no policy is configured:

```go
err := credential.Verify(mds, protocol.AttestationPolicy{}, protocol.SignaturePolicy{})
```

`VerifyAttestationType` previously took no arguments at all:

```go
// Before.
err := credential.VerifyAttestationType()

// After.
err := credential.VerifyAttestationType(config.Attestation, config.Signature)
```

#### Custom attestation formats

If you register your own attestation statement format with `protocol.RegisterAttestationFormat`, the handler
signature gained the same two policies:

```go
// Before.
func handler(att protocol.AttestationObject, clientDataHash []byte, mds metadata.Provider) (attestationType string, x5cs []any, err error)

// After.
func handler(att protocol.AttestationObject, clientDataHash []byte, mds metadata.Provider, policy protocol.AttestationPolicy, signature protocol.SignaturePolicy) (attestationType string, x5cs []any, err error)
```

Ignore both with `_` if your format has no policy of its own.

### 1.4 `protocol/webauthncose`

#### `HasherFromCOSEAlg` returns whether the algorithm is known

It previously substituted SHA-256 for any algorithm it did not recognise, which meant an unregistered algorithm in
a TPM attestation statement surfaced as a mismatched `extraData` rather than as the unsupported algorithm it was.

Before:

```go
hasher := webauthncose.HasherFromCOSEAlg(alg)
hasher.Write(data)
```

After:

```go
hasher, ok := webauthncose.HasherFromCOSEAlg(alg)
if !ok {
	return fmt.Errorf("unsupported COSE algorithm %d", alg)
}

hasher.Write(data)
```

Note the second return value is `false` both for an unregistered algorithm and for a registered one whose hash is
not linked into the binary, so it must be handled rather than asserted away.

#### `SetExperimentalInsecureAllowBERIntegers` was removed

The process-wide toggle for accepting ECDSA signatures whose integers use the padding BER permits and DER forbids
has been replaced by per-Relying-Party policy, so one process can serve two Relying Parties with different
tolerances.

Before:

```go
webauthncose.SetExperimentalInsecureAllowBERIntegers(true)
```

After:

```go
config := &webauthn.Config{
	// ...
	Signature: protocol.SignaturePolicy{
		ECDSAEncoding: protocol.ECDSASignatureEncodingBER,
	},
}
```

This remains insecure and is not recommended: accepting a non-DER signature makes the signature encoding malleable
and admits an authenticator that does not conform to the specification. Select it only where you must support a
population of authenticators known to emit such signatures. The relaxation is confined to the minimal-encoding
requirement DER places on an `INTEGER`; a signature that is not a `SEQUENCE` of exactly two positive integers, or
that carries a non-minimal length or trailing data, is still rejected.

#### `COSESignatureAlgorithmDetails`

The map's value type changed from an anonymous struct to the named `COSESignatureAlgorithmDetail`. Its fields are
unexported in both forms, so this only breaks code that declared a variable or parameter of the anonymous type.

### 1.5 `metadata`

#### `EffectiveDate` is now a pointer

`StatusReport.EffectiveDate` and `BiometricStatusReport.EffectiveDate` are `*time.Time`. The member is optional in
MDS3, and a zero `time.Time` could not be told apart from a report genuinely dated at the zero time; a
distinction that now matters, because the effective date is honoured when selecting which reports are in force
(see [§2.7](#27-status-reports-are-a-history-not-a-set)).

Before:

```go
if !report.EffectiveDate.IsZero() && report.EffectiveDate.Before(time.Now()) {
	// ...
}
```

After:

```go
if report.EffectiveDate != nil && report.EffectiveDate.Before(time.Now()) {
	// ...
}
```

`StatusReport.InEffectAt(at time.Time) bool` answers this question directly, honouring the sunset date as well, and
is what the library itself uses.

#### `CredentialExportProtocolConfigURL` was renamed

MDS 3.1.1 renamed the JSON member from `cxpConfigURL` to `cxConfigURL`. v0.17.4 carried the pre-3.1.1 name on its
tag, so it decoded a blob which used `cxpConfigURL` and left the field zero for one which used `cxConfigURL`.
Members are decoded by tag and an unmatched name is ignored rather than reported, so reading the field against
current metadata, which carries the 3.1.1 name, yielded a zero value with no error.

```go
// Before, on both metadata.Statement and metadata.StatementJSON.
statement.CredentialExportProtocolConfigURL

// After.
statement.CredentialExchangeConfigURL
```

#### `AuthenticatorGetInfo` gained members

Everything from `attestationFormats` through `authenticatorConfigCommands` is now decoded, completing CTAP 2.3
coverage; the byte string members are held as the base64 the metadata encodes them in. These are additions and
break nothing, but a struct literal without field names would not have compiled before either.

### 1.6 `webauthn.ConfigProvider`

The interface gained three methods:

```go
GetAttestationPolicy() protocol.AttestationPolicy
GetSignaturePolicy() protocol.SignaturePolicy
GetOpaqueOrigins() []string
```

`*webauthn.Config` implements all three. Only an implementation of the interface outside this module needs
changing; return the zero value from the first two, and `nil` from the third, to keep current behavior.

---

## 2. It builds, but behaves differently

### 2.1 The Relying Party ID is validated as a domain string

`protocol.ValidateRPID` previously accepted an IP address outright and applied only a superficial check to
everything else. §5.1.3 requires the origin's effective domain to be a *valid domain string* and names the address
literal as the case it excludes, so an IP Relying Party ID could never complete a ceremony; the failure was only
deferred to the client. It is now rejected where it is configured.

`webauthn.New` and both `Begin` methods return an error for a Relying Party ID which:

- is an IP address, IPv4 or IPv6;
- contains an empty label, which includes the trailing dot of a fully qualified name (`example.com.`);
- has a label beginning or ending with a hyphen;
- has a leading or trailing space, or any control character;
- contains a non-ASCII character, as no IDNA normalization is performed (see below);
- has a final label which is entirely numeric;
- exceeds 253 characters overall or 63 characters in any one label;
- is a single label other than `localhost`.

An underscore is still accepted, as the URL standard does not forbid one in a domain.

Internationalized domains must be configured as A-labels. A Relying Party ID is hashed verbatim to compare
against the `rpIdHash` an authenticator reports, while a client normalizes the value it is handed, so a name that
is not already in its ASCII form could never produce a matching hash. Apply IDNA yourself:

```go
import "golang.org/x/net/idna"

rpid, err := idna.Lookup.ToASCII("bücher.example")
if err != nil {
	return err
}

config := &webauthn.Config{RPID: rpid /* "xn--bcher-kva.example" */}
```

If you were using an IP address for local development, use `localhost` instead, which is accepted.

### 2.2 Opaque origins have their own configuration field

`Config.RPOpaqueOrigins` was added for origins which are not absolute `http` or `https` URLs with a host: the
`android:apk-key-hash:...` values an Android client reports, `chrome-extension://...`, and similar. They are
matched by exact, case-sensitive string comparison, are never matched against the Top Origin of a cross-origin
ceremony, and are never declared in the Related Origin Requests document `WebAuthn.RelatedOrigins` returns.

A Relying Party which keeps its opaque origins in `RPOrigins` is unaffected and continues to work as before, as
`RPOrigins` still falls back to simple string comparison for a value it cannot parse as a tuple origin.

Populating `RPOpaqueOrigins` opts into a stricter arrangement, so that the origins a client resolves and the
origins this Relying Party accepts cannot drift apart. Once it is set:

- `RPOrigins` and `RPTopOrigins` must contain only non-opaque origins;
- `RPOrigins` must carry no more than `protocol.MaximumRelatedOriginLabels` distinct registrable domain labels.

Either violation fails configuration validation, so `webauthn.New` returns an error.

```go
config := &webauthn.Config{
	RPID:            "example.com",
	RPOrigins:       []string{"https://example.com", "https://app.example.com"},
	RPOpaqueOrigins: []string{"android:apk-key-hash:9qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
}
```

`protocol.IsOpaqueOrigin` reports whether a given value is one, which is the same test configuration validation applies.

### 2.3 Ceremonies can be bound to a single origin

A response was previously verified against every origin in `RPOrigins`, so a ceremony begun at one of a Relying
Party's origins could be completed by a response collected at any of the others. `WithRegistrationOrigin` and
`WithLoginOrigin` bind a ceremony to one origin, recorded in `SessionData.Origin`, which is then the only origin
the finish step accepts.

```go
options, session, err := w.BeginLogin(user, webauthn.WithLoginOrigin("https://app.example.com"))
```

The bound origin must be one of those configured, so the option can only narrow, and an unconfigured value fails
when the ceremony begins rather than when it completes. An opaque origin cannot be bound, since a client conveys
one only in the response; those in `RPOpaqueOrigins` remain acceptable. The Top Origin is unaffected. A session
carrying no origin behaves exactly as before, so this is opt-in.

### 2.4 Unrequested extension outputs fail the ceremony by default

The finish step now checks that every client extension output it received corresponds to an extension this Relying
Party actually requested, and fails the ceremony otherwise. This is the zero value of the new
`Config.ExtensionsUnsolicitedOutputPolicy` field, and is the recommended setting.

If a client in your deployment is known to return outputs unprompted, and you would rather not fail a ceremony
over it:

```go
config := &webauthn.Config{
	// ...
	ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
}
```

Note this interacts with [§1.1](#11-extension-inputs-and-outputs-are-typed): the check is against what the session
records as requested, so an extension you request through `WithExtension` for a name this library does not model
is still counted as solicited.

### 2.5 Credential responses are validated more strictly

Three related changes in the parsing of a credential response:

- **`id` and `rawId` must agree, and `rawId` must be present.** Registration previously accepted a response where
  they disagreed, because the credential record is built from the attested credential ID and nothing read the
  client's value. A response which omits `rawId` or reports a different value is now rejected.
- **`URLEncodedBase64` members reject a non-string JSON value.** A number or a boolean previously decoded to
  garbage bytes rather than a parse error, because the quote trimming that allowed it removed nothing.
- **CBOR data trailing the first item is rejected.** An attestation object carrying appended bytes was previously
  accepted with the remainder silently dropped. `webauthncbor.UnmarshalFirst` remains the entry point for an item
  embedded in a larger sequence.

An `authenticatorSelection` member is also no longer emitted on creation options when it is empty; `omitempty` has
no effect on a struct value, so one was previously sent on every payload.

### 2.6 The MDS root certificate was replaced

`metadata.ProductionMDSRoot` now holds the GlobalSign Root R46 certificate, replacing the R2 certificate that
expired. If you pin the root yourself rather than relying on the default, update your pin. If you pass no root to
the decoder, nothing needs doing.

### 2.7 Status reports are a history, not a set

`metadata.ValidateStatusReports` treated its `desired` argument as a set of statuses that must each appear
*somewhere* in an authenticator's report history. Reports are a history, so that let an authenticator which is
presently `REVOKED` satisfy a certification level it held previously.

- **Desired statuses are now matched against the current status only**, and are treated as a set of acceptable
  statuses of which one must match. MDS3 requires the latest report to reflect the current status.
- **Undesired statuses are still matched against every report in effect**, because a compromise is not retracted
  by a later report.
- **`effectiveDate` and `sunsetDate` are honoured.** Reports which have not come into effect and those which have
  reached their sunset date are excluded entirely.

If you passed a list of every acceptable certification level, that still works. If you relied on a historical
status satisfying the check, it no longer will. New helpers make the selection inspectable:
`metadata.EffectiveStatusReports`, `metadata.CurrentStatusReportAt`, `metadata.ValidateStatusReportsAt` and
`StatusReport.InEffectAt`.

`WithStatusUndesired(nil)` also disables undesired-status validation entirely, including `REVOKED`, even
with `WithValidateStatus(true)`. Pass the statuses you want rejected, or leave the default in place.

### 2.8 Metadata revocation and timeouts

Revocation of an intermediate certificate was gated on the certificate carrying an issuing certificate URL, while
a leaf in the same position was rejected outright. Both now share one rule: a certificate is rejected when it is
known to be revoked.

`Fetch` and the cached provider previously created HTTP clients with no timeout, so an unresponsive metadata
service stalled the caller indefinitely. Both now use `metadata.DefaultMDSTimeout`. `Decode` also no longer closes
the reader it is given, so close it yourself if you were relying on that.

### 2.9 Registration checks the backup flags, and UV latches on assertion

`§7.1` step 17, that a credential which is not backup eligible must not report itself as backed up, is now
enforced during registration as well as authentication.

`CredentialFlags.Update` advances only the UV flag. On a credential record, `UserVerified` is the specification's
`uvInitialized` value: once an assertion has verified the user it stays true. To determine whether a *particular*
ceremony verified the user, read the UV flag of that ceremony's own authenticator data rather than the stored
credential.

### 2.10 The session Relying Party ID is honoured

A Relying Party ID overridden for a single ceremony with `WithRegistrationRelyingPartyID` or
`WithLoginRelyingPartyID` was recorded in the session but not used when verifying the response, which fell back to
`Config.RPID`. The session value is now used. If you overrode the Relying Party ID and compensated for this
elsewhere, remove the workaround.

### 2.11 ML-DSA requires Go 1.27

Support for ML-DSA-44, ML-DSA-65 and ML-DSA-87 is gated behind a `go1.27` build constraint, because the standard
library cannot verify those signatures before then. On an earlier toolchain the identifiers and
`webauthn.CredentialParametersPQCRecommendedL3` are absent rather than present and non-functional.

`CredentialParametersPQCRecommendedL3` lists the three ML-DSA parameter sets followed by EdDSA, ES256 and RS256.
The classical algorithms follow rather than being omitted because no authenticator in general use implements
ML-DSA yet; a list naming only the post-quantum algorithms would fail every registration. Name the ML-DSA
identifiers on their own if you intend to enforce a post-quantum policy.

---

## 3. Stored data

### 3.1 `webauthn.Credential` gained an `Extensions` field

`Credential.Extensions` is a `CredentialExtensions` holding the extension results recorded at registration which
remain meaningful for the life of the credential. It is populated by `CreateCredential` from the ceremony's
extension outputs.

| Field                | Type                                  | Meaning                                                      |
|----------------------|---------------------------------------|--------------------------------------------------------------|
| `RK`                 | `*bool`                               | The credential is client-side discoverable, from `credProps` |
| `CredProtect`        | `protocol.CredentialProtectionPolicy` | The credential protection policy the authenticator applied   |
| `MinPinLength`       | `*uint`                               | The authenticator's minimum PIN length at registration       |
| `PRFEnabled`         | `*bool`                               | The pseudo-random function is available for this credential  |
| `LargeBlobSupported` | `*bool`                               | The credential supports large blob storage                   |
| `HMACSecret`         | `*bool`                               | A CTAP `hmac-secret` was provisioned                         |
| `CredBlobSet`        | `*bool`                               | The blob submitted at registration was stored                |

Every pointer field distinguishes "not reported" from `false`, so store them nullable.

If you store `credProps.rk` yourself, in the `discoverable` column many integrations keep, `Extensions.RK` is now
the library's own record of it, taken from the typed outputs. You can keep your column and populate it from
`credential.Extensions.RK`, or store the whole structure.

`HMACSecret` and `CredBlobSet` are worth persisting even if you have no use for them today: they determine whether
requesting `WithExtensionHMACGetSecret` or `WithExtensionGetCredBlob` at authentication can succeed, and the
answer cannot be recovered after the registration ceremony has ended.

If you marshal `Credential` with `encoding/json` or the generated msgp methods, nothing needs doing beyond a
schema change if you decompose the struct into columns. The msgp field key is `ext`, and the generated decoder
skips unknown keys, so records written by v0.17.x decode under v0.18.0 with a zero `Extensions`.

### 3.2 Sessions in flight across the upgrade

`SessionData.Extensions` changed type (see [§1.1](#11-extension-inputs-and-outputs-are-typed)) and therefore
changed serialized shape, under both its JSON tag `extensions` and its msgp key, which changed from `exts`
holding the raw inputs to `exts` holding the session subset.

A session serialized by v0.17.x and finished by v0.18.0 will not carry a `requested` list. Under the default
unsolicited-output policy of [§2.4](#24-unrequested-extension-outputs-fail-the-ceremony-by-default), such a
ceremony fails if the client returns any client extension output, because nothing in the restored session
identifies that output as requested. A ceremony whose client returns no extension output is unaffected, whether or
not it asked for one.

The `appid` value path is separate and survives the upgrade: `SessionExtensions.AppID` uses the same `appid` JSON
key the old inputs map did, so `GetAppID` still resolves. It is the `requested` list, which the old shape has no
counterpart for, that is missing.

Drain or invalidate in-flight sessions as part of the upgrade. Ceremony sessions are short-lived by design, so
in practice this means deploying during a quiet period, or briefly setting
`ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore` across the rollout and removing it
afterwards. Sessions which requested no extensions are unaffected.

### 3.3 Carried over from v0.17.0

If you are upgrading from v0.16.x or earlier and have not yet done this, it still applies. The
`Credential.AttestationType` field previously held the attestation statement *format* (`packed`, `tpm`, `none`),
and `Credential.AttestationFormat` was added to hold it. `Credential.UnmarshalJSON` migrates a record
automatically: where the decoded record has no `AttestationFormat` and `AttestationType` holds a recognised format
identifier, the value is moved and `AttestationType` is cleared, so the true attestation type can be re-derived by
calling `Credential.VerifyAttestationType`.

The migration runs on `encoding/json` decoding only. If you read these two columns directly out of a database,
apply it yourself; `protocol.IsAttestationFormatString` is the same test the library uses:

```go
if credential.AttestationFormat == "" && protocol.IsAttestationFormatString(credential.AttestationType) {
	credential.AttestationFormat = credential.AttestationType
	credential.AttestationType = ""
}

if err = credential.VerifyAttestationType(config.Attestation, config.Signature); err != nil {
	// ...
}
```

`protocol.CredentialTypeFIDOU2F` was removed in v0.17.0; use
`protocol.AttestationFormatFIDOUniversalSecondFactor`. It is a `protocol.AttestationFormat` rather than a plain
`string`, so convert it where the other side is a plain string, such as `Credential.AttestationFormat`:

```go
if credential.AttestationFormat == string(protocol.AttestationFormatFIDOUniversalSecondFactor) {
	// ...
}
```

Use the constant directly wherever a `protocol.AttestationFormat` is expected, such as
`protocol.RegisterAttestationFormat`.

---

## 4. Configuration

New `webauthn.Config` fields. Every zero value preserves either the previous behavior or the behavior the
specification requires, except `ExtensionsUnsolicitedOutputPolicy`; see
[§2.4](#24-unrequested-extension-outputs-fail-the-ceremony-by-default).

| Field                               | Type                               | Zero value                              | Notes                                                                  |
|-------------------------------------|------------------------------------|-----------------------------------------|------------------------------------------------------------------------|
| `RPOpaqueOrigins`                   | `[]string`                         | No opaque origins configured separately | [§2.2](#22-opaque-origins-have-their-own-configuration-field)          |
| `Attestation`                       | `protocol.AttestationPolicy`       | Most restrictive available              | [§1.3](#13-verification-functions-take-policy-arguments)               |
| `Signature`                         | `protocol.SignaturePolicy`         | DER only, as the specification requires | [§1.4](#14-protocolwebauthncose)                                       |
| `ExtensionsUnsolicitedOutputPolicy` | `protocol.UnsolicitedOutputPolicy` | Reject (a behavior change)              | [§2.4](#24-unrequested-extension-outputs-fail-the-ceremony-by-default) |

`Attestation` carries two decisions:

```go
config.Attestation = protocol.AttestationPolicy{
	// Evaluate the §8.4 origin and purpose requirements against the union of the teeEnforced and
	// softwareEnforced authorization lists, which additionally accepts software-backed keys. The default,
	// AndroidKeyAuthorizationScopeTEEEnforced, accepts only keys generated in a trusted execution environment.
	AndroidKey: protocol.AndroidKeyPolicy{
		AuthorizationScope: protocol.AndroidKeyAuthorizationScopeUnion,
	},

	// Accept a compound attestation when any one sub-statement verifies. The default,
	// CompoundSubStatementScopeAll, requires every sub-statement to verify.
	Compound: protocol.CompoundPolicy{
		SubStatementScope: protocol.CompoundSubStatementScopeAny,
	},
}
```

Each has an explicit `...Default` constant which configuration validation rewrites to the restrictive choice, so
an unset field can be told apart from a deliberate selection of the same behavior.

---

## 5. Deprecations

These still work and are not yet breaking changes. Migrate at your convenience; they will be removed in a future
release.

| Deprecated                                                          | Replacement                                             |
|---------------------------------------------------------------------|---------------------------------------------------------|
| `webauthn.WithAppIdExtension(appid)`                                | `WithAssertionExtensions(WithExtensionAppID(appid))`    |
| `webauthn.WithAppIdExcludeExtension(appid)`                         | `WithExtensions(WithExtensionAppIDExclude(appid))`      |
| `protocol.CollectedClientData.TokenBinding`                         | None; removed from the IDL by WebAuthn Level 3          |
| `protocol.TokenBinding` / `protocol.TokenBindingStatus`             | None; as above                                          |
| `metadata.Statement.KeyScope` and `metadata.StatementJSON.KeyScope` | None; removed from the Metadata Statement in MDS 3.1.1  |

The two AppID options are worth migrating for a reason beyond tidiness: they are order-dependent with respect to
`WithAllowedCredentials` and `WithExclusions` respectively, because both discard the AppID unless the relevant
credential list contains a `fido-u2f` credential. The extension options are applied after the credential lists are
built and so give the same result whatever order you supply them in.

The MDS 3.1.1 members are retained and marked deprecated rather than removed, so consumers of older blobs are
unaffected; they are never populated from current metadata.

---

## Appendix: incompatible symbols

The complete list, as reported by `gorelease -base=v0.17.4`. Every entry is covered by a section above.

### `metadata`

- `BiometricStatusReport.EffectiveDate`: `time.Time` → `*time.Time`
- `StatusReport.EffectiveDate`: `time.Time` → `*time.Time`
- `ProductionMDSRoot`: value changed
- `Statement.CredentialExportProtocolConfigURL`: removed
- `StatementJSON.CredentialExportProtocolConfigURL`: removed

### `protocol`

- `AuthenticationExtensions`: `map[string]any` → struct
- `AuthenticationExtensionsClientOutputs`: `map[string]any` → struct
- `Extensions`: removed
- `(*AttestationObject).Verify`: gained `AttestationPolicy`, `SignaturePolicy`
- `(*AttestationObject).VerifyAttestation`: gained `AttestationPolicy`, `SignaturePolicy`
- `(*CollectedClientData).Verify`: gained `rpOpaqueOrigins`
- `(*ParsedCredentialAssertionData).Verify`: gained `rpOpaqueOrigins`, `SignaturePolicy`
- `(*ParsedCredentialCreationData).Verify`: gained `rpOpaqueOrigins`, `AttestationPolicy`, `SignaturePolicy`
- `ParsedPublicKeyCredential.GetAppID`: takes `SessionExtensions`
- attestation format handler signature: gained `AttestationPolicy`, `SignaturePolicy`

### `protocol/webauthncose`

- `COSESignatureAlgorithmDetails`: value type is now the named `COSESignatureAlgorithmDetail`
- `HasherFromCOSEAlg`: returns `(hash.Hash, bool)`
- `SetExperimentalInsecureAllowBERIntegers`: removed

### `webauthn`

- `(*Credential).Verify`: gained `AttestationPolicy`, `SignaturePolicy`
- `(*Credential).VerifyAttestationType`: gained `AttestationPolicy`, `SignaturePolicy`
- `ConfigProvider`: gained `GetAttestationPolicy`, `GetSignaturePolicy`, `GetOpaqueOrigins`
- `LoginOption`: now returns `error`
- `RegistrationOption`: now returns `error`
- `SessionData.Extensions`: now `protocol.SessionExtensions`
- `WithAssertionExtensions`: now `func(...ExtensionOption) LoginOption`
- `WithExtensions`: now `func(...ExtensionOption) RegistrationOption`
