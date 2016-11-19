package mobilepay

import (
	"crypto/ecdsa"
	"encoding/json"
)

type DecryptedToken struct {
	Dpan        string
	ExpireMonth int
	ExpireYear  int
	Method      string
	Cryptogram  string
	Eci         string
}

type EncryptedToken interface {
	VerifyThenDecrypt(privkey *ecdsa.PrivateKey) (*DecryptedToken, error)
}

type AndroidPayToken struct {
	EncryptedMessage   string
	EphemeralPublicKey string
	Tag                string
}

func (apt *AndroidPayToken) VerifyThenDecrypt(privkey *ecdsa.PrivateKey) (*DecryptedToken, error) {
	decrypted, err := decryptAndroidPayToken(privkey, apt)
	if err != nil {
		return nil, err
	}

	var token interface{}
	err = json.Unmarshal(decrypted, &token)
	mapping := token.(map[string]interface{})

	return &DecryptedToken{
		mapping["dpan"].(string),
		mapping["expirationMonth"].(int),
		mapping["expirationYear"].(int),
		mapping["authMethod"].(string),
		mapping["3dsCryptogram"].(string),
		mapping["3dsEciIndicator"].(string),
	}, err
}

type ApplePayToken struct {
}

func (apt *ApplePayToken) VerifyThenDecrypt(privkey *ecdsa.PrivateKey) (*DecryptedToken, error) {
	decrypted, err := decryptApplePayToken(privkey, apt)
	if err != nil {
		return nil, err
	}

	var token interface{}
	err = json.Unmarshal(decrypted, &token)
	mapping := token.(map[string]interface{})

	return &DecryptedToken{
		mapping["dpan"].(string),
		mapping["expirationMonth"].(int),
		mapping["expirationYear"].(int),
		mapping["authMethod"].(string),
		mapping["3dsCryptogram"].(string),
		mapping["3dsEciIndicator"].(string),
	}, err
}
