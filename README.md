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

When an Android Pay request comes in JSON will look something like this:
```json
{
  "encryptedMessage": "ZW5jcnlwdGVkTWVzc2FnZQ==",
  "ephemeralPublicKey": "ZXBoZW1lcmFsUHVibGljS2V5",
  "tag": "c2lnbmF0dXJl"
}
```

Those fields are reflected in the `mobilepay.AndroidPayToken` struct so add them
as well as a pointer to your `ecdsa.PrivateKey`.
```golang
block, _ := pem.Decode(pemPrivateKeyBytes)
privKey, _ := x509.ParseECPrivateKey(block.Bytes)

var request interface{}
json.Unmarshal(jsonBytes, &request)
mapping := request.(map[string]string)

token := &mobilepay.AndroidPayToken{
	mapping["encryptedMessage"],
	mapping["ephemeralPublicKey"],
	mapping["tag"],
	privKey,
}
```
*Note* in the above code snippet we assume that the private key is stored in 
PEM format. You'll have to figure out how to decode your private key if it's 
in another format.

Now that you have an AndroidPayToken value you can call `VerifyThenDecrypt` on
it to decrypt it and do whatever you need to with the decrypted value.
```golang
decrypted, err := token.VerifyThenDecrypt()
if err == nil {
	// Something went wrong
} else {
	// Store the decrypted token or send it to a payment processor
}
```

Apple Pay
---------

*Coming Soon!!!*