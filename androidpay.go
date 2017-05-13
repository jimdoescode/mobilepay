package mobilepay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func androidPayVerifyAndDecrypt(msg, epk, tag []byte, mpk *ecdsa.PrivateKey) ([]byte, error) {
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, epk)
	if x == nil {
		return nil, fmt.Errorf("Could not unmarshal ephemeral public key")
	}

	if (x.Sign() == 0 && y.Sign() == 0) || x.Cmp(curve.Params().P) >= 0 || y.Cmp(curve.Params().P) >= 0 || !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("Invalid ephemeral public key")
	}

	public := &ecdsa.PublicKey{curve, x, y}

	// Generate the shared secret by multiplying the public key with the private key
	shared, _ := elliptic.P256().ScalarMult(public.X, public.Y, mpk.D.Bytes())
	// Input keying material is the ephemeral public key concatenated with the shared secret.
	ikm := bytes.NewBuffer(elliptic.Marshal(public, public.X, public.Y))
	ikm.Write(shared.Bytes())

	// The symmetric encryption key and mac keys are generated by
	// performing an HKDF operation on the input keying material.
	// Relying on the go behavior that zeros newly allocated memory
	salt := make([]byte, 32) // since the hash is sha256 we use 256 / 8 = 32
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm.Bytes())

	prk := extract.Sum(nil)

	// We only do one iteration through the expand step as that's all that's
	// required for AndroidPay.
	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte("Android"))
	expand.Write([]byte{1})

	t := expand.Sum(nil)

	// The first half of the HKDF result is the symmetric encryption key the
	// second half is the mac key.
	symEncKey := t[:16]
	macKey := t[16:]

	// Hashing the mac key and the encrypted message should result
	// in the tag value.
	tagHash := hmac.New(sha256.New, macKey)
	tagHash.Write(msg)

	// hmac.Equal is a constant time comparison
	if !hmac.Equal(tag, tagHash.Sum(nil)) {
		return nil, fmt.Errorf("Invalid cryptogram")
	}

	// According to the AndroidPay documentation we use AES128 CTR mode with
	// a zero IV, no padding, and the symmetric encryption key
	block, err := aes.NewCipher(symEncKey)
	if err != nil {
		return nil, fmt.Errorf("Could not generate cipher block %v", err)
	}

	decrypted := make([]byte, len(msg))
	// Relying on the go behavior that zeros newly allocated memory
	iv := make([]byte, block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(decrypted, msg)

	return decrypted, nil
}
