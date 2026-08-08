package webauthn_test

import (
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ExampleWithExtensions demonstrates requesting extensions during a registration ceremony, including an extension
// this library does not model.
func ExampleWithExtensions() {
	var options protocol.PublicKeyCredentialCreationOptions

	err := webauthn.WithExtensions(
		webauthn.WithExtensionCredProps(),
		webauthn.WithExtensionLargeBlobSupport(protocol.LargeBlobSupportPreferred),
		webauthn.WithExtension("vendorThing", true),
	)(&options)
	if err != nil {
		panic(err)
	}

	fmt.Println(options.Extensions.CredProps)
	fmt.Println(options.Extensions.LargeBlob.Support)
	fmt.Println(options.Extensions.Extra["vendorThing"])

	// Output:
	// true
	// preferred
	// true
}

// ExampleParseAuthenticationExtensions demonstrates migrating a map of extension inputs written against a previous
// release. The conversion is explicit and fallible; no functional option accepts a map.
func ExampleParseAuthenticationExtensions() {
	extensions, err := protocol.ParseAuthenticationExtensions(map[string]any{"credProps": true})
	if err != nil {
		panic(err)
	}

	var options protocol.PublicKeyCredentialCreationOptions

	if err = webauthn.WithExtensions(webauthn.WithExtensionInputs(extensions))(&options); err != nil {
		panic(err)
	}

	fmt.Println(options.Extensions.CredProps)

	// Output:
	// true
}
