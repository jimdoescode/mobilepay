package mobilepay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

const MERCHANT_PRIVATE_KEY_PKCS8_BASE64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjjchHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm"

func TestAndroidPayTokenDecryption(t *testing.T) {
	merchPrivKeyBuf, _ := base64.StdEncoding.DecodeString(MERCHANT_PRIVATE_KEY_PKCS8_BASE64)
	privkey, _ := x509.ParsePKCS8PrivateKey(merchPrivKeyBuf)

	ecdsaPrivKey := privkey.(*ecdsa.PrivateKey)

	// This test cryptogram should be decrypted by the merchant private key and decrypts to "plaintext"
	token := AndroidPayToken{
		"PHxZxBQvVWwP",
		"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE=",
		"TNwa3Q2WiyGi/eDA4XYVklq08KZiSxB7xvRiKK3H7kE=",
	}

	decrypted, err := decryptAndroidPayToken(ecdsaPrivKey, &token)
	if err != nil {
		t.Errorf("Could not decrypted token: %v", err)
	}

	if bytes.Compare(decrypted, []byte("plaintext")) != 0 {
		t.Errorf("Invalid token result: %v", decrypted)
	}
}
