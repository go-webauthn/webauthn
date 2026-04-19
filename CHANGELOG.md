# [0.17.0](https://github.com/go-webauthn/webauthn/compare/v0.16.5...v0.17.0) (2026-04-20)


* fix!: split attestation type and format (#658) ([3c1e870](https://github.com/go-webauthn/webauthn/commit/3c1e8703d88f7c00ddf1a2946603d5c3641ef199)), closes [#658](https://github.com/go-webauthn/webauthn/issues/658) [#476](https://github.com/go-webauthn/webauthn/issues/476)
* feat!: tighten cross-origin defaults (#647) ([80cc224](https://github.com/go-webauthn/webauthn/commit/80cc224097df85b60b4433d12a9bb72fee45c06b)), closes [#647](https://github.com/go-webauthn/webauthn/issues/647)


### Bug Fixes

* **protocol:** short-circuit apple attestation extension lookup ([#664](https://github.com/go-webauthn/webauthn/issues/664)) ([5296bc7](https://github.com/go-webauthn/webauthn/commit/5296bc7b64de96fb430708087a6425d4c3de950c))


### Features

* **webauthn:** add authenticator registration filtering ([#668](https://github.com/go-webauthn/webauthn/issues/668)) ([0be632e](https://github.com/go-webauthn/webauthn/commit/0be632e52bb5d3a50ba78de56e658d8d55a0c969))
* **webauthn:** credential message pack ([#660](https://github.com/go-webauthn/webauthn/issues/660)) ([c7d933c](https://github.com/go-webauthn/webauthn/commit/c7d933c68a3851bbd954e0bc782d365286560016))


### BREAKING CHANGES

* A bug with the Credential Record which was
  introduced early in the libraries lifecycle has resulted in a
  breaking change to the Credential struct. If you are manually
  serializing this struct instead of using encoding/json you
  will be required to make manual changes; though Integrators
  should consider these notes regardless.

  - protocol.CredentialTypeFIDOU2F has been removed;
    replace uses with protocol.AttestationFormatFIDOUniversalSecondFactor
    (cast to string where the destination field is a plain string).

  - The semantics of the AttestationType field on webauthn.Credential
    and protocol.CredentialDescriptor have changed. Integrators that
    inspect this field to detect a format (typically checking for
    "fido-u2f") must switch to the new AttestationFormat field; the
    FIDO-U2F AppID and AppIDExclude extension helpers now key on
    AttestationFormat, so a descriptor literal constructed with
    AttestationType: "fido-u2f" will no longer trigger them.

  - Stored Credential JSON records are migrated transparently by the
    new UnmarshalJSON, but re-marshaled records will carry
    attestationFormat rather than a format string in attestationType;
    downstream consumers that parsed the legacy shape directly should
    be updated.

  - The Credential.Verify method has been updated and may fail in
    previous scenarios where it passed previously. It will also update
    the AttestationFormat value as a side-effect when used.

* The Cross-Origin verification semantics have changed
  significantly due to the stabilization of the WebAuthn Level 3
  specification. It is no longer possible to disable verification, and
  Cross-Origin ceremonies must explicitly be allowed in this release.

  - protocol.TopOriginIgnoreVerificationMode has been removed. Code that
    referenced it must switch to one of the other constants as there is
    no longer a mode which disables the Top Origin verification such as:
      - TopOriginExplicitVerificationMode; match against RPTopOrigins only
        (recommended, and the new coerced default)
      - TopOriginAutoVerificationMode; match against the union of
        RPTopOrigins and RPOrigins
      - TopOriginImplicitVerificationMode; match against RPOrigins only

  - webauthn.Config.validate now rewrites a zero-valued
    RPTopOriginVerificationMode to TopOriginExplicitVerificationMode.
    Integrators that left the field unset previously got ignore-mode
    semantics (any Top Origin accepted); they now get strict matching
    against RPTopOrigins and must populate that list, or explicitly
    select a different mode; for Cross-Origin flows to succeed.

  - Cross-Origin ceremonies (those where the authenticator reports
    crossOrigin = true in the ClientData) are rejected by default.
    Integrators that rely on iframe-embedded or other Cross-Origin WebAuthn
    flows must set webauthn.Config.RPAllowCrossOrigin = true. The library
    continues to enforce Top Origin verification on accepted Cross-Origin
    ceremonies per the configured mode.

  - protocol.CollectedClientData.Verify no longer accepts
    TopOriginIgnoreVerificationMode; callers that pass an unknown mode
    receive ErrNotImplemented with detail "unknown Top Origin
    verification mode".

## [0.16.5](https://github.com/go-webauthn/webauthn/compare/v0.16.4...v0.16.5) (2026-04-19)


### Bug Fixes

* **protocol:** validate packed attca country ([#656](https://github.com/go-webauthn/webauthn/issues/656)) ([819edc8](https://github.com/go-webauthn/webauthn/commit/819edc8bc47301a6e1ad02fc486d3028c1f02e0b))
* **webauthn:** ensure challenge length is valid ([#657](https://github.com/go-webauthn/webauthn/issues/657)) ([85e9e68](https://github.com/go-webauthn/webauthn/commit/85e9e6840c6f48a70ac0813288591aee64d3a77c))

## [0.16.4](https://github.com/go-webauthn/webauthn/compare/v0.16.3...v0.16.4) (2026-04-09)

## [0.16.3](https://github.com/go-webauthn/webauthn/compare/v0.16.2...v0.16.3) (2026-04-05)


### Bug Fixes

* **webauthncose:** replace elliptic ([#635](https://github.com/go-webauthn/webauthn/issues/635)) ([3b8a663](https://github.com/go-webauthn/webauthn/commit/3b8a66332363096814dcace4997491dfb8513109))


### Features

* **metadata:** update metadata authenticator statuses ([#641](https://github.com/go-webauthn/webauthn/issues/641)) ([95d28bc](https://github.com/go-webauthn/webauthn/commit/95d28bc22f60654dc33a36fcd52abd637b94cbf3))
* **webauthncose:** add dilithium cose types ([#636](https://github.com/go-webauthn/webauthn/issues/636)) ([4106b24](https://github.com/go-webauthn/webauthn/commit/4106b24d9673f9808764fdcbafbc60aa07123d5d))

## [0.16.2](https://github.com/go-webauthn/webauthn/compare/v0.16.1...v0.16.2) (2026-03-30)


### Bug Fixes

* top origins always fails ([#626](https://github.com/go-webauthn/webauthn/issues/626)) ([514306b](https://github.com/go-webauthn/webauthn/commit/514306bbc73c84e76cca3ef33b3d928861726cce))
* **webauthn:** credential flags not fully updated ([#629](https://github.com/go-webauthn/webauthn/issues/629)) ([a4b68c8](https://github.com/go-webauthn/webauthn/commit/a4b68c826204543163c1e54bfeb48c9b67fead25))
* **webauthn:** nil panic on discovery ([#631](https://github.com/go-webauthn/webauthn/issues/631)) ([3545ead](https://github.com/go-webauthn/webauthn/commit/3545ead0397a1ed1e7dab17049067aa3b3104c85))


### Features

* **webauthn:** messagepack encoding ([#621](https://github.com/go-webauthn/webauthn/issues/621)) ([bf8fe28](https://github.com/go-webauthn/webauthn/commit/bf8fe281ed422d07e48e4bd978519e4fa09821b2))

## [0.16.1](https://github.com/go-webauthn/webauthn/compare/v0.16.0...v0.16.1) (2026-03-12)


### Bug Fixes

* **webauthncose:** validate keys earlier ([#615](https://github.com/go-webauthn/webauthn/issues/615)) ([18ca901](https://github.com/go-webauthn/webauthn/commit/18ca90110d09f5f21db5f77da9a207e4661ee8ac))

# [0.16.0](https://github.com/go-webauthn/webauthn/compare/v0.15.0...v0.16.0) (2026-03-01)


### Bug Fixes

* **webauthn:** empty top origins not allowed ([#562](https://github.com/go-webauthn/webauthn/issues/562)) ([fe3b74c](https://github.com/go-webauthn/webauthn/commit/fe3b74cc51cb91517a9a2e4c08c0a09678e9c241)), closes [#537](https://github.com/go-webauthn/webauthn/issues/537)
* **webauthn:** session expiration not enforced ([#561](https://github.com/go-webauthn/webauthn/issues/561)) ([f5adbbf](https://github.com/go-webauthn/webauthn/commit/f5adbbfe379b6205eb691f7208d7d9b8398b1a8a)), closes [#552](https://github.com/go-webauthn/webauthn/issues/552)


### Features

* **protocol:** compound attestation statements ([#571](https://github.com/go-webauthn/webauthn/issues/571)) ([cc4e649](https://github.com/go-webauthn/webauthn/commit/cc4e649184291fe47f75a155e4d637393c654d3e))
* **protocol:** enhance rpid validation ([#564](https://github.com/go-webauthn/webauthn/issues/564)) ([7610304](https://github.com/go-webauthn/webauthn/commit/76103040326cd7c2a7fa25887eddec389e5bc554)), closes [#553](https://github.com/go-webauthn/webauthn/issues/553)
* **protocol:** signals structs ([#574](https://github.com/go-webauthn/webauthn/issues/574)) ([f75a34a](https://github.com/go-webauthn/webauthn/commit/f75a34a516d4f72c68a231d0b6452841d864f579))
* **webauthncose:** allow ber integers in ecdsa sigs ([#593](https://github.com/go-webauthn/webauthn/issues/593)) ([68db4d4](https://github.com/go-webauthn/webauthn/commit/68db4d4d7d82a06801ea3c5fbe39e1c5397caf95)), closes [#408](https://github.com/go-webauthn/webauthn/issues/408)
* **webauthn:** return explicit error on unknown credential ([#560](https://github.com/go-webauthn/webauthn/issues/560)) ([1defb4a](https://github.com/go-webauthn/webauthn/commit/1defb4abfee87733face86ef96bb356ee4a0d4d0)), closes [#550](https://github.com/go-webauthn/webauthn/issues/550)

# [0.15.0](https://github.com/go-webauthn/webauthn/compare/v0.14.0...v0.15.0) (2025-11-09)

# [0.14.0](https://github.com/go-webauthn/webauthn/compare/v0.13.4...v0.14.0) (2025-09-14)


### Bug Fixes

* **webauthn:** edge case in owned credentials validation ([#487](https://github.com/go-webauthn/webauthn/issues/487)) ([9410f91](https://github.com/go-webauthn/webauthn/commit/9410f91944874a26b2ca30d747cd19e086189ec6))
* **webauthn:** skip mds validation for none format ([#497](https://github.com/go-webauthn/webauthn/issues/497)) ([a1b2775](https://github.com/go-webauthn/webauthn/commit/a1b27757c411106085c88ba6ec36d31f3996c3ae)), closes [#387](https://github.com/go-webauthn/webauthn/issues/387)


### Features

* **metadata:** update schema to 3.1 ([#454](https://github.com/go-webauthn/webauthn/issues/454)) ([3c6b5a1](https://github.com/go-webauthn/webauthn/commit/3c6b5a1a376a24b19a1149e8aaaafedea30ca5c1))
* **protocol:** att format updates ([#485](https://github.com/go-webauthn/webauthn/issues/485)) ([c079c8b](https://github.com/go-webauthn/webauthn/commit/c079c8b87bc4e564418b86a0d9c05cbf076a10ff))
* **protocol:** update tpm manufacturers ([#496](https://github.com/go-webauthn/webauthn/issues/496)) ([46046ca](https://github.com/go-webauthn/webauthn/commit/46046cac56ea0fbfd6ce3c573da1ea5e179bf954))
* **protocol:** validate native app origins ([#468](https://github.com/go-webauthn/webauthn/issues/468)) ([0b2a549](https://github.com/go-webauthn/webauthn/commit/0b2a5491d2d7932ecfdb0312df4ab67df71595e9)), closes [#462](https://github.com/go-webauthn/webauthn/issues/462) [#463](https://github.com/go-webauthn/webauthn/issues/463)

## [0.13.4](https://github.com/go-webauthn/webauthn/compare/v0.13.3...v0.13.4) (2025-07-18)


### Bug Fixes

* **metadata:** biometric accuracy descriptor types ([#451](https://github.com/go-webauthn/webauthn/issues/451)) ([c561b4d](https://github.com/go-webauthn/webauthn/commit/c561b4d52ba983e176d818662a6dbd6d67d8ad5b)), closes [#450](https://github.com/go-webauthn/webauthn/issues/450)

## [0.13.3](https://github.com/go-webauthn/webauthn/compare/v0.13.2...v0.13.3) (2025-07-11)


### Bug Fixes

* missing helpers ([#444](https://github.com/go-webauthn/webauthn/issues/444)) ([380a944](https://github.com/go-webauthn/webauthn/commit/380a944393a56d8bd21386713a38428675f6c92e))
* **webauthn:** missing passkey tooling ([#443](https://github.com/go-webauthn/webauthn/issues/443)) ([088d7c4](https://github.com/go-webauthn/webauthn/commit/088d7c48399e3c3cd5db10e52704d7dfc623244b))

## [0.13.1](https://github.com/go-webauthn/webauthn/compare/v0.13.0...v0.13.1) (2025-07-06)


### Bug Fixes

* **protocol:** conditional create uv check ([#434](https://github.com/go-webauthn/webauthn/issues/434)) ([2e13a60](https://github.com/go-webauthn/webauthn/commit/2e13a60aecef52d91467d444a9fc66150ecee17b)), closes [#361](https://github.com/go-webauthn/webauthn/issues/361)

# [0.13.0](https://github.com/go-webauthn/webauthn/compare/v0.12.3...v0.13.0) (2025-05-08)


### Features

* **protocol:** cable transport ([#418](https://github.com/go-webauthn/webauthn/issues/418)) ([af19983](https://github.com/go-webauthn/webauthn/commit/af1998367b46fe969f015c6754549ef11a54a95f))
* **protocol:** verify alg param during registration ([#412](https://github.com/go-webauthn/webauthn/issues/412)) ([4cad90a](https://github.com/go-webauthn/webauthn/commit/4cad90a784463f23f7033992524b585954bc8d8f))

## [0.12.3](https://github.com/go-webauthn/webauthn/compare/v0.12.2...v0.12.3) (2025-04-01)


### Bug Fixes

* **webauthn:** empty aaguid fails login ([#398](https://github.com/go-webauthn/webauthn/issues/398)) ([4b7cd31](https://github.com/go-webauthn/webauthn/commit/4b7cd3180b8e2ddf79a30bd4abc38d1d13378638))

## [0.12.2](https://github.com/go-webauthn/webauthn/compare/v0.12.1...v0.12.2) (2025-03-10)

## [0.12.1](https://github.com/go-webauthn/webauthn/compare/v0.12.0...v0.12.1) (2025-02-23)

# [0.12.0](https://github.com/go-webauthn/webauthn/compare/v0.11.2...v0.12.0) (2025-02-23)


### Bug Fixes

* **metadata:** cached file update fails without write access ([#383](https://github.com/go-webauthn/webauthn/issues/383)) ([1398e76](https://github.com/go-webauthn/webauthn/commit/1398e765ca74bd4ab18d676833e1ea1b192cd98d))
* **protocol:** ensure attca is parsed correctly ([#280](https://github.com/go-webauthn/webauthn/issues/280)) ([ad0f7e2](https://github.com/go-webauthn/webauthn/commit/ad0f7e2a24436325a5d845c6635b2b62a7c0914f))
* **webauthn:** expose cred params functions ([#286](https://github.com/go-webauthn/webauthn/issues/286)) ([e736323](https://github.com/go-webauthn/webauthn/commit/e7363232b6eadb48272bbb33f9e7447b8d27651a))
* **webauthn:** login validates attestation format ([#384](https://github.com/go-webauthn/webauthn/issues/384)) ([a218507](https://github.com/go-webauthn/webauthn/commit/a2185073fa11b221ae2bcf703c35e82b4cdbe4cb))


### Features

* **protocol:** credential mediation ([#361](https://github.com/go-webauthn/webauthn/issues/361)) ([b9a233f](https://github.com/go-webauthn/webauthn/commit/b9a233f627c94835e5ad3d2bc4a63dd55140580b)), closes [#347](https://github.com/go-webauthn/webauthn/issues/347)
* **protocol:** enhance errors ([#341](https://github.com/go-webauthn/webauthn/issues/341)) ([3207315](https://github.com/go-webauthn/webauthn/commit/3207315bf5d662f7a863f3defb51e7f4bab0f2e3)), closes [#365](https://github.com/go-webauthn/webauthn/issues/365)
* **protocol:** include intermediate certificate parsing ([#345](https://github.com/go-webauthn/webauthn/issues/345)) ([339114c](https://github.com/go-webauthn/webauthn/commit/339114cc55df3e0cdd71e6ed0c093fe2aa331a09))
* **protocol:** update tpm manufacturers ([#374](https://github.com/go-webauthn/webauthn/issues/374)) ([193f5b5](https://github.com/go-webauthn/webauthn/commit/193f5b5601c4186ff988d8a8eb49548cc81826e6))
* **webauthn:** add login option to manually set challenge ([#359](https://github.com/go-webauthn/webauthn/issues/359)) ([3a57554](https://github.com/go-webauthn/webauthn/commit/3a57554407e0cf80d4c9249187529d34102bfddf)), closes [#353](https://github.com/go-webauthn/webauthn/issues/353)
* **webauthn:** include new credential flags func ([#337](https://github.com/go-webauthn/webauthn/issues/337)) ([e5657ab](https://github.com/go-webauthn/webauthn/commit/e5657ab773ac20ed803c03138bb3cd854fca7852))
* **webauthn:** json v2 partial and unsupported compat ([#327](https://github.com/go-webauthn/webauthn/issues/327)) ([bf37040](https://github.com/go-webauthn/webauthn/commit/bf370401a33135c578f12effad37db1e89b7d787))

## [0.11.2](https://github.com/go-webauthn/webauthn/compare/v0.11.1...v0.11.2) (2024-08-25)


### Bug Fixes

* **protocol:** out of date tpm manufacturers ([#283](https://github.com/go-webauthn/webauthn/issues/283)) ([13ad30e](https://github.com/go-webauthn/webauthn/commit/13ad30e184cd9fcf425b8fb238fd4595b9692a1d))

## [0.11.1](https://github.com/go-webauthn/webauthn/compare/v0.11.0...v0.11.1) (2024-08-06)


### Bug Fixes

* **metadata:** file closed too early ([#273](https://github.com/go-webauthn/webauthn/issues/273)) ([9ca2fae](https://github.com/go-webauthn/webauthn/commit/9ca2faef6e4bbc88bfbaaccca846ee420b142e17)), closes [#264](https://github.com/go-webauthn/webauthn/issues/264)
* **metadata:** functional opt sets wrong value ([#272](https://github.com/go-webauthn/webauthn/issues/272)) ([2b83ee0](https://github.com/go-webauthn/webauthn/commit/2b83ee087a0b031589ddd5c37afb6abcbaadb503))

# [0.11.0](https://github.com/go-webauthn/webauthn/compare/v0.10.2...v0.11.0) (2024-07-29)


* feat(metadata)!: rework as a provider (#239) ([6713911](https://github.com/go-webauthn/webauthn/commit/67139112f304e5b9bf38fdc5fe9438b785fe2d56)), closes [#239](https://github.com/go-webauthn/webauthn/issues/239) [#77](https://github.com/go-webauthn/webauthn/issues/77) [#154](https://github.com/go-webauthn/webauthn/issues/154)
* feat!: allow empty modality values (#257) ([a5c838a](https://github.com/go-webauthn/webauthn/commit/a5c838ae1d45fcacb9456858624143f94bc1f128)), closes [#257](https://github.com/go-webauthn/webauthn/issues/257)
* feat!: backup flag validation (#240) ([2195f33](https://github.com/go-webauthn/webauthn/commit/2195f336fc704cd7020dd84c1aad876426349434)), closes [#240](https://github.com/go-webauthn/webauthn/issues/240)
* feat!: remove deprecated values (#233) ([](https://github.com/go-webauthn/webauthn/commit/)), closes [#233](https://github.com/go-webauthn/webauthn/issues/233) [#221](https://github.com/go-webauthn/webauthn/issues/221)


### Features

* **config:** allow rpid to be defined at execution time ([#234](https://github.com/go-webauthn/webauthn/issues/234)) ([c673c3d](https://github.com/go-webauthn/webauthn/commit/c673c3df53aefa0ff054ea9d327353d42db1a93a)), closes [#165](https://github.com/go-webauthn/webauthn/issues/165)
* parse credential bytes ([#258](https://github.com/go-webauthn/webauthn/issues/258)) ([b382edc](https://github.com/go-webauthn/webauthn/commit/b382edcd9be038ebf1a2687930a65bde441a0508))
* support hints and attestation formats ([#216](https://github.com/go-webauthn/webauthn/issues/216)) ([824017d](https://github.com/go-webauthn/webauthn/commit/824017d99111c90ebee22cc4b8b7d3a01e7802f4))
* top origin verification ([#217](https://github.com/go-webauthn/webauthn/issues/217)) ([0c97761](https://github.com/go-webauthn/webauthn/commit/0c97761a14b4f9d6aa71eb0c3b0f30b365aa7eb9)), closes [#205](https://github.com/go-webauthn/webauthn/issues/205)
* webauthn level 3 ([#232](https://github.com/go-webauthn/webauthn/issues/232)) ([482cf89](https://github.com/go-webauthn/webauthn/commit/482cf89b770bf7938afab1626d3a0fbb95eedd67))


### BREAKING CHANGES

* This change will require manual intervention from the implementer. Information is likely to be provided at a later date helping with the migrations required.
* This change will change default behaviour. Previously the required resident key value was set to false, and the user verification option was set to 'preferred'.
* This breaks implementations which do not strictly adhere to the specification. Several major providers either have or are currently "upgrading" existing WebAuthn credential records to BE and BS passkeys.

Co-authored-by: zahra.keshtkar <zahra.keshtkar@snapp.cab>
* the following fields and backwards compatible elements have been removed; Icon field from the CredentialEntity struct, WebAuthnIcon function from the User interface, RPIcon/RPOrigin/Timeout fields from the Config struct, Transports field from the CredentialCreationResponse (new field has existed in the AuthenticatorAttestationResponse struct for quite some time which matches the spec).

## [0.10.2](https://github.com/go-webauthn/webauthn/compare/v0.10.1...v0.10.2) (2024-03-13)

## [0.10.1](https://github.com/go-webauthn/webauthn/compare/v0.10.0...v0.10.1) (2024-02-08)

# [0.10.0](https://github.com/go-webauthn/webauthn/compare/v0.9.4...v0.10.0) (2023-12-20)


### Features

* credential struct tags for json serialization ([#197](https://github.com/go-webauthn/webauthn/issues/197)) ([99b2e0d](https://github.com/go-webauthn/webauthn/commit/99b2e0da2f31927c6cfeeb96849a6a0f2aad1dec))

## [0.9.4](https://github.com/go-webauthn/webauthn/compare/v0.9.3...v0.9.4) (2023-12-02)


### Bug Fixes

* **protocol:** trailing credential data skipped ([#191](https://github.com/go-webauthn/webauthn/issues/191)) ([e5a5571](https://github.com/go-webauthn/webauthn/commit/e5a55712ba72edcad25b1b20f342741c1ee59a34)), closes [#189](https://github.com/go-webauthn/webauthn/issues/189)

## [0.9.3](https://github.com/go-webauthn/webauthn/compare/v0.9.2...v0.9.3) (2023-12-01)


### Bug Fixes

* timeout config not propagating ([#188](https://github.com/go-webauthn/webauthn/issues/188)) ([1fc32f2](https://github.com/go-webauthn/webauthn/commit/1fc32f20894d770faaef90453d55ccb77c66f8d5))

## [0.9.2](https://github.com/go-webauthn/webauthn/compare/v0.9.1...v0.9.2) (2023-11-28)


### Bug Fixes

* **protocol:** display name omitted incorrectly ([#184](https://github.com/go-webauthn/webauthn/issues/184)) ([a602b39](https://github.com/go-webauthn/webauthn/commit/a602b39285e539f56c9c7292fded8c13290725d2)), closes [#183](https://github.com/go-webauthn/webauthn/issues/183)

## [0.9.1](https://github.com/go-webauthn/webauthn/compare/v0.9.0...v0.9.1) (2023-11-18)


### Bug Fixes

* **protocol:** previous unmarshal functionality broken ([#180](https://github.com/go-webauthn/webauthn/issues/180)) ([68d2368](https://github.com/go-webauthn/webauthn/commit/68d236807509dca5fab44a5ac27ab0bd8594f1f1))

# [0.9.0](https://github.com/go-webauthn/webauthn/compare/v0.8.6...v0.9.0) (2023-11-18)


### Features

* helper/convenience finish login function for discoverable functions ([#173](https://github.com/go-webauthn/webauthn/issues/173)) ([9cc24fa](https://github.com/go-webauthn/webauthn/commit/9cc24fad30f85634ede26412cb1bbbbe7bf803d1)), closes [#172](https://github.com/go-webauthn/webauthn/issues/172)

## [0.8.6](https://github.com/go-webauthn/webauthn/compare/v0.8.5...v0.8.6) (2023-07-18)

## [0.8.5](https://github.com/go-webauthn/webauthn/compare/v0.8.4...v0.8.5) (2023-07-16)


### Bug Fixes

* **protocol:** attestation type attca not validated correctly ([#153](https://github.com/go-webauthn/webauthn/issues/153)) ([44d68a6](https://github.com/go-webauthn/webauthn/commit/44d68a6c4f25bb54040b3f41dd6fdb490ad3e054)), closes [#149](https://github.com/go-webauthn/webauthn/issues/149)

## [0.8.4](https://github.com/go-webauthn/webauthn/compare/v0.8.3...v0.8.4) (2023-07-06)

## [0.8.3](https://github.com/go-webauthn/webauthn/compare/v0.8.2...v0.8.3) (2023-06-28)


### Bug Fixes

* error hidden during discoverable login ([#142](https://github.com/go-webauthn/webauthn/issues/142)) ([a942e60](https://github.com/go-webauthn/webauthn/commit/a942e60673534beb77dadee1dfd5f4e39c82ecca)), closes [#140](https://github.com/go-webauthn/webauthn/issues/140)
* unnecessary field in session data ([#141](https://github.com/go-webauthn/webauthn/issues/141)) ([30ee1f3](https://github.com/go-webauthn/webauthn/commit/30ee1f31a4c20e82df8460ccaa30682a151d850e))

## [0.8.2](https://github.com/go-webauthn/webauthn/compare/v0.8.1...v0.8.2) (2023-02-22)


### Bug Fixes

* **protocol:** expose ccr/car parse method ([#128](https://github.com/go-webauthn/webauthn/issues/128)) ([709be4f](https://github.com/go-webauthn/webauthn/commit/709be4f6e0357862b4a5fcda5d27aff2d8dda6a4))

## [0.8.1](https://github.com/go-webauthn/webauthn/compare/v0.8.0...v0.8.1) (2023-02-19)


### Bug Fixes

* error returned from new is inconsistent ([#126](https://github.com/go-webauthn/webauthn/issues/126)) ([cd86a1f](https://github.com/go-webauthn/webauthn/commit/cd86a1f7909c38fbb01548091ea0f95ac29f2c4e))

# [0.8.0](https://github.com/go-webauthn/webauthn/compare/v0.7.2...v0.8.0) (2023-02-19)


### Bug Fixes

* validate configuration on all begin methods ([#125](https://github.com/go-webauthn/webauthn/issues/125)) ([e42df0d](https://github.com/go-webauthn/webauthn/commit/e42df0d620dcc651f23a39da1896c1dca7a834d4))


### Features

* session expiration ([#109](https://github.com/go-webauthn/webauthn/issues/109)) ([e1d245d](https://github.com/go-webauthn/webauthn/commit/e1d245d53355def12c72049c907e4166299b2cbe))
* **webauthn:** allow encoding user.id as a string ([#124](https://github.com/go-webauthn/webauthn/issues/124)) ([0948c14](https://github.com/go-webauthn/webauthn/commit/0948c14faea9ea1a612988e57cd7979a1ca2494a))

## [0.7.2](https://github.com/go-webauthn/webauthn/compare/v0.7.1...v0.7.2) (2023-02-15)


### Bug Fixes

* **protocol:** creation invalid transports path ([#113](https://github.com/go-webauthn/webauthn/issues/113)) ([3c168f4](https://github.com/go-webauthn/webauthn/commit/3c168f4c1e54703dceb8c5207ba5ffff41967c34))
* **protocol:** missing attachment field ([#114](https://github.com/go-webauthn/webauthn/issues/114)) ([3386584](https://github.com/go-webauthn/webauthn/commit/3386584efdaeff405d0fdf18aaf8aeda66142d4d))
* **webauthn:** missing important flag info from credential ([#117](https://github.com/go-webauthn/webauthn/issues/117)) ([1ee3a4a](https://github.com/go-webauthn/webauthn/commit/1ee3a4aecef1f7d5a43a5ff882f2832e90dc215b))
* **webauthn:** missing user display name from session ([#116](https://github.com/go-webauthn/webauthn/issues/116)) ([a51f98d](https://github.com/go-webauthn/webauthn/commit/a51f98d6cd070b7c67a44b250e192e25dcd1e6d0))


### Reverts

* fix(webauthn): missing user display name from session ([#120](https://github.com/go-webauthn/webauthn/issues/120)) ([33e2a9d](https://github.com/go-webauthn/webauthn/commit/33e2a9d221b110c3435ba33f08a0668f38ac41fa))

## [0.7.1](https://github.com/go-webauthn/webauthn/compare/v0.7.0...v0.7.1) (2023-02-11)


### Bug Fixes

* missing base64 url encoding ([#110](https://github.com/go-webauthn/webauthn/issues/110)) ([42e66d8](https://github.com/go-webauthn/webauthn/commit/42e66d82e8d21867443f2e4a7c9234ee4d84d726))

# [0.7.0](https://github.com/go-webauthn/webauthn/compare/v0.6.1...v0.7.0) (2023-01-29)


### Bug Fixes

* **webauthncose:** potential nil ptr in ec unmarshal ([#102](https://github.com/go-webauthn/webauthn/issues/102)) ([c3d789d](https://github.com/go-webauthn/webauthn/commit/c3d789d39298d018c3fa9f3869be4a829f145b5c))


### Features

* **protocol:** add enterprise attestation preference ([#100](https://github.com/go-webauthn/webauthn/issues/100)) ([ad214bd](https://github.com/go-webauthn/webauthn/commit/ad214bd6cc9adcb18d39422bcd0e14f05575e251)), closes [#90](https://github.com/go-webauthn/webauthn/issues/90)
* **protocol:** ignore padding for base64 url encoding ([#95](https://github.com/go-webauthn/webauthn/issues/95)) ([dca408e](https://github.com/go-webauthn/webauthn/commit/dca408e85f0ae0b78c25661a594f1dabfb61f1c7)), closes [#93](https://github.com/go-webauthn/webauthn/issues/93)
* **protocol:** native android fido2 origin ([#94](https://github.com/go-webauthn/webauthn/issues/94)) ([5f46788](https://github.com/go-webauthn/webauthn/commit/5f46788ebc9c0946a05085151dced4f13ef90277)), closes [#92](https://github.com/go-webauthn/webauthn/issues/92)

## [0.6.1](https://github.com/go-webauthn/webauthn/compare/v0.6.0...v0.6.1) (2023-01-28)


### Bug Fixes

* **metadata:** mds3 tests failure due to url change ([#96](https://github.com/go-webauthn/webauthn/issues/96)) ([83e3622](https://github.com/go-webauthn/webauthn/commit/83e3622388c50352ecbcc94a0f3ae32cff01de57))
* **protocol:** user entity id not encoded correctly ([#98](https://github.com/go-webauthn/webauthn/issues/98)) ([3d8dfc7](https://github.com/go-webauthn/webauthn/commit/3d8dfc7668ef8027c2e92fb928fefeabe9799f2f)), closes [#97](https://github.com/go-webauthn/webauthn/issues/97)

# [0.6.0](https://github.com/go-webauthn/webauthn/compare/v0.5.0...v0.6.0) (2022-12-18)


### Bug Fixes

* **challenge:** urlsafe base64 encoding ([#82](https://github.com/go-webauthn/webauthn/issues/82)) ([6abd351](https://github.com/go-webauthn/webauthn/commit/6abd3517301412ba1f6a25c0d88ce59b22a463c6))
* google tpm ec mapping ([#43](https://github.com/go-webauthn/webauthn/issues/43)) ([6be1bd6](https://github.com/go-webauthn/webauthn/commit/6be1bd6daf4269ff4ff26a39e928c28914f1b022))
* **protocol:** potential panic in u2f attestation ([#46](https://github.com/go-webauthn/webauthn/issues/46)) ([59c2424](https://github.com/go-webauthn/webauthn/commit/59c2424fe7d35c9c40d68a4db7c84a84a7049b81))


### Features

* add config option to add multiple rp origins ([#81](https://github.com/go-webauthn/webauthn/issues/81)) ([0bba500](https://github.com/go-webauthn/webauthn/commit/0bba50041d236c1cfd0f16c8ac633c5281d038a1)), closes [#76](https://github.com/go-webauthn/webauthn/issues/76)
* expose credential parameter configuration ([#40](https://github.com/go-webauthn/webauthn/issues/40)) ([46f365d](https://github.com/go-webauthn/webauthn/commit/46f365d6efaa59d822cda3a784cd91fe2053c8ae))
* **metadata:** mds3 support ([#54](https://github.com/go-webauthn/webauthn/issues/54)) ([697bc4c](https://github.com/go-webauthn/webauthn/commit/697bc4cb16d3cfc8755bd946b55b9699e76a4510))
* **protocol:** added authentication transportation hybrid ([#86](https://github.com/go-webauthn/webauthn/issues/86)) ([752defd](https://github.com/go-webauthn/webauthn/commit/752defd2c4567585a48f1a2ead648b80ecd39da9)), closes [#74](https://github.com/go-webauthn/webauthn/issues/74)
* **protocol:** implement device eligible and backup flags ([#85](https://github.com/go-webauthn/webauthn/issues/85)) ([694d289](https://github.com/go-webauthn/webauthn/commit/694d2895a150a7e83140dc8931449835869d71d3)), closes [#75](https://github.com/go-webauthn/webauthn/issues/75)
* refactor of tpm attestation ([#60](https://github.com/go-webauthn/webauthn/issues/60)) ([cdfc867](https://github.com/go-webauthn/webauthn/commit/cdfc8674dbeaed1b48b28bc87c364dffe132b104))

## [0.3.3](https://github.com/go-webauthn/webauthn/compare/v0.3.2...v0.3.3) (2022-06-24)


### Bug Fixes

* **webauthn:** potential panic in parse fido public key ([#39](https://github.com/go-webauthn/webauthn/issues/39)) ([3551cfa](https://github.com/go-webauthn/webauthn/commit/3551cfae24f258cd9c978a73711fb9551f82d1e4))

## [0.3.2](https://github.com/go-webauthn/webauthn/compare/v0.3.1...v0.3.2) (2022-06-24)

## [0.3.1](https://github.com/go-webauthn/webauthn/compare/v0.3.0...v0.3.1) (2022-04-13)

# [0.3.0](https://github.com/go-webauthn/webauthn/compare/v0.2.2...v0.3.0) (2022-04-06)


### Features

* **deps:** remove module github.com/cloudflare/cfssl ([#33](https://github.com/go-webauthn/webauthn/issues/33)) ([c561447](https://github.com/go-webauthn/webauthn/commit/c561447e218d73421476565a3d66ab6dc934966c))

## [0.2.2](https://github.com/go-webauthn/webauthn/compare/v0.2.1...v0.2.2) (2022-03-29)


### Reverts

* remove resident key unrequired method ([#30](https://github.com/go-webauthn/webauthn/issues/30)) ([bd4f996](https://github.com/go-webauthn/webauthn/commit/bd4f9968158dbea4247eb0d8ec27954e27ae8be3))

## [0.2.1](https://github.com/go-webauthn/webauthn/compare/v0.2.0...v0.2.1) (2022-03-01)

# [0.2.0](https://github.com/go-webauthn/webauthn/compare/v0.1.1...v0.2.0) (2022-03-01)


### Bug Fixes

* check the credential id length att data ([#16](https://github.com/go-webauthn/webauthn/issues/16)) ([b3b93ac](https://github.com/go-webauthn/webauthn/commit/b3b93ac3770a26a92adbcd4b527bbb391127931b))
* parse all transports even if unknown ([#14](https://github.com/go-webauthn/webauthn/issues/14)) ([729227d](https://github.com/go-webauthn/webauthn/commit/729227d1ec0504ebb518f38e72bcd10ae68c4130))
* unused json tag ([#17](https://github.com/go-webauthn/webauthn/issues/17)) ([4c7efcd](https://github.com/go-webauthn/webauthn/commit/4c7efcd6731b80d51eab5ca8a6772a86c83e6b30))


### Features

* add resident key protocol option ([#13](https://github.com/go-webauthn/webauthn/issues/13)) ([5ad54f8](https://github.com/go-webauthn/webauthn/commit/5ad54f89952eb238a7d6e10ed2d443738351d67f))
* add with setters for appid related extensions ([#11](https://github.com/go-webauthn/webauthn/issues/11)) ([d3212fe](https://github.com/go-webauthn/webauthn/commit/d3212fedb34b790da7c7e0440baa0fd47fe7ca4d))
* discoverable login ([#18](https://github.com/go-webauthn/webauthn/issues/18)) ([401a3f6](https://github.com/go-webauthn/webauthn/commit/401a3f63b5fb3c91faa52c56a9295b78d62e039f))

## [0.1.1](https://github.com/go-webauthn/webauthn/compare/v0.1.0...v0.1.1) (2022-03-01)


### Bug Fixes

* appid check ([#3](https://github.com/go-webauthn/webauthn/issues/3)) ([b71d523](https://github.com/go-webauthn/webauthn/commit/b71d5233dc921b8f75940e4cf50edc8af1659e03))
* encode hashes as hex ([#6](https://github.com/go-webauthn/webauthn/issues/6)) ([4697513](https://github.com/go-webauthn/webauthn/commit/469751312636bdd9dc6ebc17e3c9f07b474e99c1))
* incorrect usage of subtle ([#7](https://github.com/go-webauthn/webauthn/issues/7)) ([70316cb](https://github.com/go-webauthn/webauthn/commit/70316cb5115d86ba0855b7d98a3633b5767e0708))
* potential index out of range panic ([#8](https://github.com/go-webauthn/webauthn/issues/8)) ([2bbb113](https://github.com/go-webauthn/webauthn/commit/2bbb113b333b775d2d7c5551b7220f713f666f00))
* use ctap2 cbor ([#5](https://github.com/go-webauthn/webauthn/issues/5)) ([497fae3](https://github.com/go-webauthn/webauthn/commit/497fae3f394dc5d758ba7dc366188f9c254bc4d9))

# [0.1.0](https://github.com/go-webauthn/webauthn/compare/8065b78cf2cbd34f1a5a5d2a4b74fc107ac77c89...v0.1.0) (2021-12-15)


### Bug Fixes

* missing extension results in parsed credential data ([#13](https://github.com/go-webauthn/webauthn/issues/13)) ([9c370fd](https://github.com/go-webauthn/webauthn/commit/9c370fd4159bb1a8b5341dfd8614538c5f3eae1d))
* vuln sign count update on clone detected ([#3](https://github.com/go-webauthn/webauthn/issues/3)) ([5098308](https://github.com/go-webauthn/webauthn/commit/509830883101cde459c437aedef8a4b3bd1c9777))
* **webauthn:** allowed credentials validation iteration logic failure ([#10](https://github.com/go-webauthn/webauthn/issues/10)) ([525b8d2](https://github.com/go-webauthn/webauthn/commit/525b8d288a19344f6b8b4c5b9a345bfd81f6c143))
* **webauthn:** config not honored in begin registration ([#12](https://github.com/go-webauthn/webauthn/issues/12)) ([f846cca](https://github.com/go-webauthn/webauthn/commit/f846cca4c4f897dd3151822f5e2f3a9b3505a690))


### Features

* accept transports information ([#8](https://github.com/go-webauthn/webauthn/issues/8)) ([738efed](https://github.com/go-webauthn/webauthn/commit/738efed6b093713170fd15a2779afa9d3826e9b9))
* appid extension ([#7](https://github.com/go-webauthn/webauthn/issues/7)) ([509e08f](https://github.com/go-webauthn/webauthn/commit/509e08fb364c78be30067a93d976730a8fe4a656))


### Reverts

* Revert "added codec tags for effortless attestation parsing (#14)" ([8065b78](https://github.com/go-webauthn/webauthn/commit/8065b78cf2cbd34f1a5a5d2a4b74fc107ac77c89)), closes [#14](https://github.com/go-webauthn/webauthn/issues/14)
