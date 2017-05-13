Mobile Payment Decryption
=========================

This go library will evetually contain all the code necessary to decrypt an 
Apple and Android Pay request. The decryption should be done in a PCI environment 
and then the decrypted result can be passed to a payment processor to auth the
card.

Android Pay
-----------

The first step in handling Android Pay is to generate an elliptic curve 
public/private key pair. You'll put the public key in your Android app and use 
it as part of the `MaskedWalletRequest`. Keep the private key in your PCI 
environment and make sure it is properly secured. Checkout
[the docs](https://developers.google.com/android-pay/integration/payment-token-cryptography#example-using-openssl-to-generate-and-format-a-public-key)
for more details on how to create an elliptic curve public and private key.

When an encrypted Android Pay request comes in, the JSON will look something like this:
```json
{
  "encryptedMessage": "ZW5jcnlwdGVkTWVzc2FnZQ==",
  "ephemeralPublicKey": "ZXBoZW1lcmFsUHVibGljS2V5",
  "tag": "c2lnbmF0dXJl"
}
```

Those fields as well as a pointer to your `ecdsa.PrivateKey` are passed to `NewAndroidPayDecryptedToken`. 
```golang
block, _ := pem.Decode(pemPrivateKeyBytes)
privKey, _ := x509.ParseECPrivateKey(block.Bytes)

var request interface{}
json.Unmarshal(jsonBytes, &request)
mapping := request.(map[string]string)

decrypted, err := NewAndroidPayDecryptedToken(
	mapping["encryptedMessage"],
	mapping["ephemeralPublicKey"],
	mapping["tag"],
	privKey,
)
```
**Note** there is no timing data in the request json, you're responsible for making 
sure that decryption requests aren't a replay request.

If `NewAndroidPayDecryptedToken` returns a valid DecryptedToken value and not an
error then you're good to go! Either hand the token off to your payment processor
or store it and return a token for future payment handling.

Apple Pay
---------

*Coming Soon!!!*
