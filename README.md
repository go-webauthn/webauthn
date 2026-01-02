# WebAuthn Library

[![GoDoc](https://godoc.org/github.com/go-webauthn/webauthn?status.svg)](https://godoc.org/github.com/go-webauthn/webauthn)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-webauthn/webauthn)](https://goreportcard.com/report/github.com/go-webauthn/webauthn)
[![Version](https://img.shields.io/github/release/go-webauthn/webauthn.svg)](https://github.com/go-webauthn/webauthn/releases)
![Go version](https://img.shields.io/badge/Go-1.25-brightgreen.svg)
[![codecov](https://codecov.io/github/go-webauthn/webauthn/graph/badge.svg?token=P1FN91DTLE)](https://codecov.io/github/go-webauthn/webauthn)
[![License](https://img.shields.io/github/license/go-webauthn/webauthn?color=blue)](https://github.com/go-webauthn/webauthn?tab=BSD-3-Clause-1-ov-file#readme)

This library is meant to handle [Web Authentication](https://www.w3.org/TR/webauthn) for Go apps that wish to implement 
a multi-factor authentication, passwordless, or usernameless solution for users. This library conforms as much as
possible to the guidelines and implementation procedures outlined by the relevant specifications and is conformance
tested against the conformance tools.

## Go Version Support Policy

This library; unless otherwise explicitly expressed; will officially support the latest minor version of go, and will
only offer best effort support for versions of go which are currently supported by the go maintainers (usually 3 minor
versions) with a brief transition time (usually 1 patch release of go, for example if go 1.21.0 is released, we will
likely still support go 1.17 until go 1.21.1 is released). These specific rules apply at the time of a published
release.

This library is intended to be used with [Go Toolchains](https://go.dev/doc/toolchain) as indicated by the
`toolchain` directive in the `go.mod`.

This library in our opinion handles a critical element of security in a dependent project and we aim to avoid backwards
compatibility at the cost of security wherever possible. We also consider this especially important in a language like
go where their backwards compatibility when upgrading the compile tools is usually flawless.

This policy means that users who wish to build this with older versions of go may find there are features being used
which are not available in that version. The current intentionally supported versions of go are as follows:

- go 1.25
- go 1.24
- ~~go 1.23~~ (not supported by golang.org/x/crypto v0.42.0)

## Status

This library is still version 0, as per Semantic Versioning 2.0 rules there may be breaking changes without warning. 
While we strive to avoid such changes and strive to notify users they may be unavoidable.

## Quickstart

First run `go get github.com/go-webauthn/webauthn` and initialize it in your application with basic configuration
values.

Make sure your `user` model is able to handle the interface functions laid out in the
[webauthn.User](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#User) interface. This means also
supporting the storage and retrieval of the [webauthn.Credential] struct which can be encoded fairly easily.

## Notable Changes

The notable breaking changes made by this library are documented in the [breaking changes](BREAKING.md) documentation.

## Examples

The examples are documented in the [go docs -> webauthn -> examples].

## Documentation

The intent is to move all documentation into the [go docs], and a good starting place is the [go docs -> webauthn]
location.

### Credential Record

**_Important:_** It is considered critical that implementers carefully read the [webauthn.Credential] struct
documentation as part of the implementation process.

The WebAuthn Level 3 specification describes the Credential Record which includes several required and optional elements
that you should store for. See [§ 4 Terminology](https://www.w3.org/TR/webauthn-3/#credential-record) for details.

This section describes this element.

The fields listed in the specification have corresponding fields in the [webauthn.Credential] struct. See the below
table for more information. We also include JSON mappings for those that wish to just store these values as JSON.

|    Specification Field    |       Library Field        |         JSON Field         |                                                                      Notes                                                                      |
|:-------------------------:|:--------------------------:|:--------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------:|
|           type            |            N/A             |            N/A             |                                                 This field is always `public-key` for WebAuthn.                                                 |
|            id             |             ID             |             id             |                                                                                                                                                 |
|         publicKey         |         PublicKey          |         publicKey          |                                                                                                                                                 |
|     attestationFormat     |      AttestationType       |      attestationType       |                                      This field is currently named incorrectly and this will be corrected.                                      |
|         signCount         |  Authenticator.SignCount   |  authenticator.signCount   |                                                                                                                                                 |
|        transports         |         Transport          |         transport          |                                                                                                                                                 |
|       uvInitialized       |     Flags.UserVerified     |     flags.userVerified     |                                                                                                                                                 |
|      backupEligible       |    Flags.BackupEligible    |    flags.backupEligible    |                                                                                                                                                 |
|        backupState        |     Flags.BackupState      |     flags.backupState      |                                                                                                                                                 |
|            N/A            |        Attestation         |        attestation         | This field is a composite object containing fields from the Credential Record and additional fields to assist in validation of this Credential. |
|     attestationObject     |     Attestation.Object     |     attestation.object     |                                                                                                                                                 |
| attestationClientDataJSON | Attestation.ClientDataJSON | attestation.clientDataJSON |                                                                                                                                                 |

#### Flags

It's important to note that the recommendations and requirements for flag storage have changed over the course of the
evolution of the WebAuthn specification. We at the present time only make the flags classified like this available for
easy storage however we also make the Protocol Value available. At such a time as these recommendations or requirements
change we will adapt accordingly. The Protocol Value is a raw representation of the flags and as such is resistant to
breaking changes whereas the other flags or lack thereof may not be. 

Implementers are therefore encouraged to use
[func (CredentialFlags) ProtocolValue](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#CredentialFlags.ProtocolValue)
to retrieve the raw value and 
[webauthn.NewCredentialFlags](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#NewCredentialFlags) to 
restore it; and instead of using the individual flags to store the value store the Protocol Value, and only store the
individual flags as a means to perform compliance related decisions.

#### Storage

It is also important to note that restoring the [webauthn.Credential] with the correct values will likely affect the
validity of the [webauthn.Credential], i.e. if some values are not restored the [webauthn.Credential] may fail
validation in this scenario.

#### Verification

As long as the [webauthn.Credential] struct has exactly the same values when restored the [Credential Verify] function 
can be leveraged to verify the credential against the [metadata.Provider]. This can be either done during registration,
on every login, or with a audit schedule.

In addition to using the [Credential Verify] function the 
[webauthn.Config](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#Config) can contain a provider which will
process all registrations automatically.

At this time no tooling exists to verify the credential automatically outside the registration flow. Implementation of
this is considered domain logic and beyond the scope of what we provide documentation for; we just provide the necessary
tooling to implement this yourself.

## Support

This section indicates various support statuses for specific elements of the spec. The level column indicates the spec
level this library currently supports for that statement format by the first number, and the number in parenthesis
represents when the format was introduced into the spec.

### Attestation Format

|                                                          Format                                                           |     Identifier      |  Supported  | Level |
|:-------------------------------------------------------------------------------------------------------------------------:|:-------------------:|:-----------:|:-----:|
|            [§8.2 Packed Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-packed-attestation)            |      `packed`       |     Yes     | 3 (1) |
|               [§8.3 TPM Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-tpm-attestation)               |        `tpm`        |     Yes     | 3 (1) |
|       [§8.4 Android Key Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-android-key-attestation)       |    `android-key`    |     Yes     | 3 (1) |
| [§8.5 Android SafetyNet Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-android-safetynet-attestation) | `android-safetynet` |     Yes     | 3 (1) |
|          [§8.6 FIDO U2F Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-fido-u2f-attestation)          |     `fido-u2f`      |     Yes     | 3 (1) |
|              [§8.7 None Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-none-attestation)              |       `none`        |     Yes     | 3 (1) |
|   [§8.8 Apple Anonymous Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-apple-anonymous-attestation)   |       `apple`       |     Yes     | 3 (2) |
|         [§8.9 Compound Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation)         |     `compound`      | In Progress | 3 (3) |

### Extensions

Standardized and Specification Listed Extensions:

|                                                                                   Extension                                                                                    |   Identifier   | Supported (Registration) | Supported (Authentication) | Level |
|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:--------------:|:------------------------:|:--------------------------:|:-----:|
|                                              [§10.1.1 FIDO AppID Extension](https://www.w3.org/TR/webauthn/#sctn-appid-extension)                                              |    `appid`     |         N/A[^2]          |        Yes (manual)        | 3 (1) |
|                                     [§10.1.2 FIDO AppID Exclusion Extension](https://www.w3.org/TR/webauthn/#sctn-appid-exclude-extension)                                     | `appidExclude` |       Yes (manual)       |          N/A[^1]           | 3 (1) |
|                        [§10.1.3 Credential Properties Extension](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension)                         |  `credProps`   |       Yes (manual)       |          N/A[^1]           | 3 (2) |
|                                       [§10.1.5 Large Blob Storage Extension](https://www.w3.org/TR/webauthn/#sctn-large-blob-extension)                                        |  `largeBlob`   |       Yes (manual)       |        Yes (manual)        | 3 (2) |

CTAP2 Extensions Which Are Largely unsupported:

|                                                                                             Extension                                                                                             |      Identifier       | Supported (Registration) | Supported (Authentication) |
|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:---------------------:|:------------------------:|:--------------------------:|
|          [Credential Protection Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-credProtect-extension)           |     `credProtect`     |       Yes (manual)       |          N/A[^1]           |
|               [Credential Blob Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-credBlob-extension)               |      `credBlob`       |       Yes (manual)       |        Yes (manual)        | 
|             [Large Blob Key Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-largeBlobKey-extension)              |    `largeBlobKey`     |       Yes (manual)       |        Yes (manual)        |
|           [Minimum PIN Length Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-minpinlength-extension)            |    `minPinLength`     |       Yes (manual)       |        Yes (manual)        |
|          [PIN Complexity Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-pincomplexitypolicy-extension)          | `pinComplexityPolicy` |       Yes (manual)       |          N/A[^1]           | 
|               [HMAC Secret Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-hmac-secret-extension)                |     `hmac-secret`     |       Yes (manual)       |        Yes (manual)        | 
|   [HMAC Secret MakeCredential Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-hmac-secret-make-cred-extension)   |   `hmac-secret-mc`    |         N/A[^2]          |        Yes (manual)        | 
| [Third-Party Payment Authentication Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-thirdPartyPayment-extension) |  `thirdPartyPayment`  |       Yes (manual)       |        Yes (manual)        |

[^1]: This extension is only applicable during Registration.
[^2]: This extension is only applicable during Authentication.

Extensions that have been deprecated and removed from the spec. The deprecated level is the first spec level that did
not include the extension. These are all technically supported by the extensions map, but have no official support from
this library, and are most likely not supported by either browsers or authenticators.

These extensions often either were excluded due to privacy or security concerns, were introduced into the core of the
spec as legitimate inputs outside of extensions, or never received support from browsers or authenticators.

|                                                                  Format                                                                   |      Identifier       | Level (Added) | Level (Deprecated) |
|:-----------------------------------------------------------------------------------------------------------------------------------------:|:---------------------:|:-------------:|:------------------:|
|              [Generic Transaction Authorization Extension](https://www.w3.org/TR/webauthn-1/#sctn-generic-txauth-extension)               |    `txAuthGeneric`    |       1       |         2          |
|               [Authenticator Selection Extension](https://www.w3.org/TR/webauthn-1/#sctn-authenticator-selection-extension)               |      `authnSel`       |       1       |         2          |
|                  [Supported Extensions Extension](https://www.w3.org/TR/webauthn-1/#sctn-supported-extensions-extension)                  |        `exts`         |       1       |         2          |
|                         [User Verification Index Extension](https://www.w3.org/TR/webauthn-1/#sctn-uvi-extension)                         |         `uvi`         |       1       |         2          |
|                              [Location Extension](https://www.w3.org/TR/webauthn-1/#sctn-location-extension)                              |         `loc`         |       1       |         2          |
|                        [User Verification Method Extension](https://www.w3.org/TR/webauthn-1/#sctn-uvm-extension)                         |         `uvm`         |       1       |         3          |
| [Biometric Authenticator Performance Bounds Extension](https://www.w3.org/TR/webauthn-1/#sctn-authenticator-biometric-criteria-extension) | `biometricPerfBounds` |       1       |         2          |

## Acknowledgements

We graciously acknowledge the original authors of this library [github.com/duo-labs/webauthn] for their amazing
implementation. In particular we'd like to acknowledge [Nick Steele](https://github.com/nicksteele) who not only created
the original library, but maintained it, and has been an active member of the WebAuthn Working Group quite some time. 
Without their amazing work this library could not exist.

[github.com/duo-labs/webauthn]: https://github.com/duo-labs/webauthn
[webauthn.Credential]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#Credential
[metadata.Provider]: https://pkg.go.dev/github.com/go-webauthn/webauthn/metadata#Provider
[Credential Verify]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#Credential.Verify

[go docs]: https://pkg.go.dev/github.com/go-webauthn/webauthn

[go docs -> webauthn]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn

[go docs -> webauthn -> examples]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#pkg-examples