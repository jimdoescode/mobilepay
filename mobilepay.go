// Package mobilepay provides functionality for decrypting mobile
// payment requests like those from Apple or Android Pay.
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

// NewAndroidPayDecryptedToken checks that the android pay token data is valid
// then decrypts it returning a pointer to the DecryptedToken. An error is
// returned if the android pay token is invalid or there was a problem
// decrypting it. For more documentation on Android Pay decryption check out
// https://developers.google.com/android-pay/integration/payment-token-cryptography
func NewAndroidPayDecryptedToken(ephemeralPublicKey, encryptedMessage, tag string, merchantPrivateKey *ecdsa.PrivateKey) (*DecryptedToken, error) {
	epk, err := base64.StdEncoding.DecodeString(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode ephemeral public key %v", err)
	}

	msg, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode encrypted message %v", err)
	}

	tagb, err := base64.StdEncoding.DecodeString(tag)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode tag %v", err)
	}

	decrypted, err := androidPayVerifyAndDecrypt(epk, msg, tagb, merchantPrivateKey)
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

// NewApplePayDecryptedToken is not implemented yet.
func NewApplePayDecryptedToken() (*DecryptedToken, error) {
	return nil, fmt.Errorf("Not implemented yet!")
}
