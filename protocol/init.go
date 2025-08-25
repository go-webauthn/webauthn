package protocol

import (
	"crypto/x509"
)

func init() {
	initAndroidKeyHardwareRoots()
	initAppleHardwareRoots()
}

func initAndroidKeyHardwareRoots() {
	attAndroidKeyHardwareRootsCertPool = x509.NewCertPool()

	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot1)))
	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot2)))
	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot3)))
	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot4)))
	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509CertificatePEM([]byte(certificateAndroidKeyRoot5)))

}

func initAppleHardwareRoots() {
	attAppleHardwareRootsCertPool = x509.NewCertPool()

	attAppleHardwareRootsCertPool.AddCert(MustParseX509CertificatePEM([]byte(certificateAppleRoot1)))
}
