package webauthncose

var allowBERIntegers = false

// SetExperimentalInsecureAllowBERIntegers allows credentials which have BER integer encoding for their signatures
// which do not conform to the specification. This is an experimental option which may be removed without any notice,
// and could potentially lead to zero-day exploits due to ambiguity of encoding practices. This is not a recommended
// option.
func SetExperimentalInsecureAllowBERIntegers(value bool) {
	allowBERIntegers = value
}
