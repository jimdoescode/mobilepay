package mobilepay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"
)

func TestAndroidPayDecryption(t *testing.T) {
	merchPrivKeyBuf, _ := base64.StdEncoding.DecodeString(
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjjchHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm",
	)
	privkey, _ := x509.ParsePKCS8PrivateKey(merchPrivKeyBuf)

	ephemeralPubKey, _ := base64.StdEncoding.DecodeString("BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE=")
	encryptedMsg, _ := base64.StdEncoding.DecodeString("PHxZxBQvVWwP")
	tag, _ := base64.StdEncoding.DecodeString("TNwa3Q2WiyGi/eDA4XYVklq08KZiSxB7xvRiKK3H7kE=")

	// This test cryptogram should be decrypted by the merchant
	// private key and decrypts to the phrase "plaintext"
	decrypted, err := androidPayVerifyAndDecrypt(
		encryptedMsg,
		ephemeralPubKey,
		tag,
		privkey.(*ecdsa.PrivateKey),
	)

	if err != nil {
		t.Errorf("Could not decrypt token: %v", err)
	}

	if bytes.Compare(decrypted, []byte("plaintext")) != 0 {
		t.Errorf("Invalid token result: %v", decrypted)
	}
}

func TestAndroidPayTokenDecryption(t *testing.T) {
	// Test values below provided by https://github.com/spreedly/r2d2 Thanks!
	pkPem := []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDnEBl2fHeMqFqePupLh6RTQM6Ro16v8JjIAVXcHp4ktoAoGCCqGSM49
AwEHoUQDQgAEa6fxL04JEhOi/+1QzTHuh6d+qoEizAo79xNkJ5xvaeizZv2wBRV+
cynhOeThDf8FJDE4TIGL0G+a4zlrM3wqNw==
-----END EC PRIVATE KEY-----
`,
	)
	block, _ := pem.Decode([]byte(pkPem))
	ecdsaPrivKey, _ := x509.ParseECPrivateKey(block.Bytes)

	decrypted, err := NewAndroidPayDecryptedToken(
		"V65NNwqzK0A1bi0F96HQZr4eFA8fWCatwykv3sFA8Cg4Wn4Ylk/szN6GiFTuYQFrHA7a/h0P3tfEQd09bor6pRqrM8/Bt12R0SHKtnQxbYxTjpMr/7C3Um79n0jseaPlK8+CHXljbYifwGB+cEFh/smP8IO1iw3TL/192HesutfVMKm9zpo5mLNzQ2GMU4JWUGIgrzsew6S6XshelrjE",
		"BB9cOXHgf3KcY8dbsU6fhzqTJm3JFvzD+8wcWg0W9r+Xl5gYjoZRxHuYocAx3g82v2o0Le1E2w4sDDl5w3C0lmY=",
		"boJLmOxDduTV5a34CO2IRbgxUjZ9WmfzxNl1lWqQ+Z0=",
		ecdsaPrivKey,
	)

	if err != nil || decrypted == nil {
		t.Errorf("Could not decrypt token: %v", err)
	}

	if reflect.TypeOf(decrypted).Name() == "DecryptedToken" {
		t.Errorf("Invalid token type returned after decryption")
	}

	if decrypted.Dpan != "4895370012003478" {
		t.Errorf("Unexpected dpan value, expecting 4895370012003478 found %s", decrypted.Dpan)
	}

	if decrypted.Cryptogram != "AgAAAAAABk4DWZ4C28yUQAAAAAA=" {
		t.Errorf("Unexpected 3dsCryptogram value, expecting AgAAAAAABk4DWZ4C28yUQAAAAAA= found %s", decrypted.Cryptogram)
	}
}

func ExampleNewAndroidPayDecryptedToken() {
	//Test values provided by https://github.com/spreedly/r2d2
	pkPem := []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDnEBl2fHeMqFqePupLh6RTQM6Ro16v8JjIAVXcHp4ktoAoGCCqGSM49
AwEHoUQDQgAEa6fxL04JEhOi/+1QzTHuh6d+qoEizAo79xNkJ5xvaeizZv2wBRV+
cynhOeThDf8FJDE4TIGL0G+a4zlrM3wqNw==
-----END EC PRIVATE KEY-----
`,
	)

	block, _ := pem.Decode(pkPem)
	ecdsaPrivKey, _ := x509.ParseECPrivateKey(block.Bytes)

	decrypted, err := NewAndroidPayDecryptedToken(
		"V65NNwqzK0A1bi0F96HQZr4eFA8fWCatwykv3sFA8Cg4Wn4Ylk/szN6GiFTuYQFrHA7a/h0P3tfEQd09bor6pRqrM8/Bt12R0SHKtnQxbYxTjpMr/7C3Um79n0jseaPlK8+CHXljbYifwGB+cEFh/smP8IO1iw3TL/192HesutfVMKm9zpo5mLNzQ2GMU4JWUGIgrzsew6S6XshelrjE",
		"BB9cOXHgf3KcY8dbsU6fhzqTJm3JFvzD+8wcWg0W9r+Xl5gYjoZRxHuYocAx3g82v2o0Le1E2w4sDDl5w3C0lmY=",
		"boJLmOxDduTV5a34CO2IRbgxUjZ9WmfzxNl1lWqQ+Z0=",
		ecdsaPrivKey,
	)

	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	b, err := json.MarshalIndent(decrypted, "", "    ")
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	fmt.Printf("%s\n", b)
	// Output: {
	//     "Dpan": "4895370012003478",
	//     "ExpireMonth": "12",
	//     "ExpireYear": "2020",
	//     "Method": "3DS",
	//     "Cryptogram": "AgAAAAAABk4DWZ4C28yUQAAAAAA=",
	//     "Eci": "07"
	// }
}
