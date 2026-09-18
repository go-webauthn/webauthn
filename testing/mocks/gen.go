package mocks

//go:generate mockgen -package mocks -destination metadata.go -mock_names Provider=MockMetadataProvider github.com/go-webauthn/webauthn/metadata Provider
//go:generate mockgen -package mocks -destination metadata_extended.go -mock_names ExtendedProvider=MockMetadataExtendedProvider github.com/go-webauthn/webauthn/metadata ExtendedProvider
