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
// decrypting it. For more documentation on Android Pay encrypted token data
// and decryption check out https://developers.google.com/android-pay/integration/payment-token-cryptography
func NewAndroidPayDecryptedToken(msg, epk, tag string, mpk *ecdsa.PrivateKey) (*DecryptedToken, error) {
	rawmsg, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode encrypted message %v", err)
	}

	rawepk, err := base64.StdEncoding.DecodeString(epk)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode ephemeral public key %v", err)
	}

	rawtag, err := base64.StdEncoding.DecodeString(tag)
	if err != nil {
		return nil, fmt.Errorf("Could not b64 decode tag %v", err)
	}

	tokjson, err := androidPayVerifyAndDecrypt(rawmsg, rawepk, rawtag, mpk)
	if err != nil {
		return nil, err
	}

	var token interface{}
	decoder := json.NewDecoder(bytes.NewReader(tokjson))
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
