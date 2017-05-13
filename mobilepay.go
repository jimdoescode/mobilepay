// Package mobilepay provides functionality for decrypting mobile
// payment requests.
package mobilepay

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// DecryptedToken is what will be returned when a mobile
// payment token is successfully decrypted.
type DecryptedToken struct {
	Dpan        string
	ExpireMonth string
	ExpireYear  string
	Method      string
	Cryptogram  string
	Eci         string
}

// EncryptedToken interface is implemented by all
// encrypted mobile payment tokens.
type EncryptedToken interface {
	VerifyThenDecrypt() (*DecryptedToken, error)
}

// AndroidPayToken is the struct that should be used to decrypt an
// Android Pay request. For more details check out
// https://developers.google.com/android-pay/integration/payment-token-cryptography
type AndroidPayToken struct {
	EncryptedMessage   string
	EphemeralPublicKey string
	Tag                string
	MerchantPrivateKey *ecdsa.PrivateKey
}

// VerifyThenDecrypt implements mobilepay.EncryptedToken.VerifyThenDecrypt and
// checks that an android pay token is valid then decrypts it returning a
// pointer to the DecryptedToken. An error is returned if the android pay
// token is invalid or there was a problem decrypting it.
func (apt *AndroidPayToken) VerifyThenDecrypt() (*DecryptedToken, error) {
	epk, err := base64.StdEncoding.DecodeString(apt.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode ephemeral public key %v", err)
	}

	msg, err := base64.StdEncoding.DecodeString(apt.EncryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode encrypted message %v", err)
	}

	tag, err := base64.StdEncoding.DecodeString(apt.Tag)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode tag %v", err)
	}

	decrypted, err := androidPayVerifyAndDecrypt(epk, msg, tag, apt.MerchantPrivateKey)
	if err != nil {
		return nil, err
	}

	var token interface{}
	decoder := json.NewDecoder(bytes.NewReader(decrypted))
	decoder.UseNumber()
	if err := decoder.Decode(&token); err != nil {
		return nil, err
	}

	mapping := token.(map[string]interface{})

	return &DecryptedToken{
		mapping["dpan"].(string),
		mapping["expirationMonth"].(json.Number).String(),
		mapping["expirationYear"].(json.Number).String(),
		mapping["authMethod"].(string),
		mapping["3dsCryptogram"].(string),
		mapping["3dsEciIndicator"].(string),
	}, nil
}
