package encapsulation_sample

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"testing"
)

func Test_generateEphemeralKeyPair(t *testing.T) {
	// we use the test vector from Mastering Ethereum: https://github.com/ethereumbook/ethereumbook/blob/develop/04keys-addresses.asciidoc
	// private key: 0xf8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315
	// public key x: 0x6e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b
	// public key y: 0x83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0
	// address: 0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9
	priv, _ := hexutil.Decode("0xf8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315")
	if "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9" != roundTrip(priv) {
		t.Fail()
	}
}

func roundTrip(privateKey []byte) string {
	version := "secp256k1-aes-128-gcm"
	pub, e := derivePublicKey(version, hexutil.Encode(privateKey))
	if e != nil {
		fmt.Println(e.Error())
		return ""
	}
	fmt.Println("pub: " + pub)

	generateWalletEntry(privateKey)

	R, e := generateEphemeralKeyPair(version, "")
	if e != nil {
		fmt.Println(e.Error())
		return ""
	}
	fmt.Println("R: " + R)

	oob := []byte("123456")
	salt := []byte("eip-kem")
	cipher, e := wrapPrivateKey(version, R, "", oob, salt, "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9")
	if e != nil {
		fmt.Println(e.Error())
		return ""
	}
	fmt.Println("cipher: " + cipher)
	decryptedAccount, _ := intakePrivateKey(version, R, oob, salt, cipher)

	fmt.Println(decryptedAccount)

	return decryptedAccount
}
