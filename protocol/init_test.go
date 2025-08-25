package protocol

func init() {
	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509CertificatePEM([]byte(certificateAndroidKeyIntermediateFAKE1)))
	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509CertificatePEM([]byte(certificateAndroidKeyIntermediateFAKE2)))
}
