package protocol

import "crypto/x509"

func init() {
	attAndroidKeyHardwareRootsCertPool = x509.NewCertPool()

	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509Certificate(attAndroidKeyHardwareRoot3))
	attAndroidKeyHardwareRootsCertPool.AddCert(MustParseX509Certificate(attAndroidKeyHardwareRoot4))
}
