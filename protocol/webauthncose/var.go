package webauthncose

var allowBERIntegers = false

// SetExperimentalInsecureAllowBERIntegers allows credentials which have BER integer encoding for their signatures
// which do not conform to the specification. This is an experimental option which may be removed without any notice,
// and could potentially lead to zero-day exploits due to ambiguity of encoding practices. This is not a recommended
// option. This function is not safe for concurrent use and must only be called during process initialization,
// before any verifications are performed, and its value must not be changed thereafter.
func SetExperimentalInsecureAllowBERIntegers(value bool) {
	allowBERIntegers = value
}
