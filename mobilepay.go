package mobilepay

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type DecryptedToken struct {
	Dpan        string
	ExpireMonth string
	ExpireYear  string
	Method      string
	Cryptogram  string
	Eci         string
}

type EncryptedToken interface {
	VerifyThenDecrypt() (*DecryptedToken, error)
}

type AndroidPayToken struct {
	EncryptedMessage   string
	EphemeralPublicKey string
	Tag                string
	MerchantPrivateKey *ecdsa.PrivateKey
}

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
	}, err
}
