package protocol

import "crypto/x509"

func init() {
	attAndroidKeyHardwareRoots := make([]*x509.Certificate, 5)

	attAndroidKeyHardwareRoots[0] = MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot1))
	attAndroidKeyHardwareRoots[1] = MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot2))
	attAndroidKeyHardwareRoots[2] = MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot3))
	attAndroidKeyHardwareRoots[3] = MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot4))
	attAndroidKeyHardwareRoots[4] = MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot5))

	insecureMangleCertsNotAfter(attAndroidKeyHardwareRoots)

	attAndroidKeyHardwareRootsCertPool = x509.NewCertPool()

	for _, cert := range attAndroidKeyHardwareRoots {
		attAndroidKeyHardwareRootsCertPool.AddCert(cert)
	}
}
