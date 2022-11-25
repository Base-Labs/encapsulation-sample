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
	account := "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9"

	//r, _ := generatePrivateKey()
	//s, _ := generatePrivateKey()
	//signer, _ := generatePrivateKey()
	//trusted, _ := generatePrivateKey()

	fmt.Println("r: " + hexutil.Encode(r))
	fmt.Println("s: " + hexutil.Encode(s))
	fmt.Println("signer: " + hexutil.Encode(signer))
	fmt.Println("trusted: " + hexutil.Encode(trusted))

	// case 1
	version := "secp256k1-AES-128-GCM"
	fmt.Println("-----------------------------------")
	if account != roundTrip(version, priv) {
		t.Fail()
	} else {
		fmt.Println("passed 1")
	}

	// case 2
	fmt.Println("-----------------------------------")
	version = "secp256k1-AES-256-GCM"

	if account != roundTrip(version, priv) {
		t.Fail()
	} else {
		fmt.Println("passed 2")
	}

	// case 3
	fmt.Println("-----------------------------------")
	version = "Curve25519-Chacha20-Poly1305"

	if account != roundTrip(version, priv) {
		t.Fail()
	} else {
		fmt.Println("passed 3")
	}

	// case 4
	fmt.Println("-----------------------------------")
	version = "Curve25519-AES-128-GCM"

	if account != roundTrip(version, priv) {
		t.Fail()
	} else {
		fmt.Println("passed 4")
	}
}

func roundTrip(version string, privateKey []byte) string {
	addr := generateWalletEntry(privateKey)
	fmt.Println("private key to be encapsulate: " + hexutil.Encode(privateKey))
	fmt.Println("corresponding address (account): " + addr)

	oob := []byte("123456")
	salt := []byte("eip: private key encapsulation")
	fmt.Println("oob: " + hexutil.Encode(oob))
	fmt.Println("salt: " + hexutil.Encode(salt))

	R, _ := derivePublicKey(version, hexutil.Encode(r), false)
	S, _ := derivePublicKey(version, hexutil.Encode(s), false)
	signerPubKey, _ := derivePublicKey(version, hexutil.Encode(signer), true)
	trustedPubKey, _ := derivePublicKey(version, hexutil.Encode(trusted), true)

	fmt.Println("R: " + R)
	fmt.Println("S: " + S)
	fmt.Println("signerPubKey: " + signerPubKey)
	fmt.Println("trustedPubKey: " + trustedPubKey)

	sig, _ := signInVersion(version, R, signer)
	sig2, _ := signInVersion(version, signerPubKey, trusted)

	Rsig := R + hexutil.Encode(sig)[2:]
	Singersig := signerPubKey + hexutil.Encode(sig2)[2:]

	cipher, e := wrapPrivateKey(version, Rsig, Singersig, oob, salt, addr)
	if e != nil {
		fmt.Println(e.Error())
		return ""
	}

	fmt.Println("cipher text returned from wrapping: " + cipher)

	decryptedAccount, _ := intakePrivateKey(version, R, oob, salt, cipher)

	fmt.Println("account returned from decryption (and address derivation): " + decryptedAccount)

	return decryptedAccount
}
