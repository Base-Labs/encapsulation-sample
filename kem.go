package encapsulation_sample

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
	"strings"
)

// implementation MUST keep the key pairs securely, below is insecure and just for demo purposes
var insecureHolderSecp256k1 = map[string]([]byte){}
var insecureHolderEd25519 = map[string](ed25519.PrivateKey){}
var inseaureWallet = map[string]([]byte){} // address -- private key mapping for Ethereum

func generatePrivateKey() ([]byte, error) {
	privateKey := make([]byte, 32)
	_, e := rand.Read(privateKey)
	if e != nil {
		return nil, e
	}
	return privateKey, nil
}

func derivePublicKey(version string, privateKey string) (compressedPub string, err error) {
	if len(version) == 0 {
		return "", errors.New("version must not be empty")
	}

	v := strings.ToLower(version)
	var pubKey []byte

	priv, e := hexutil.Decode(privateKey)
	if e != nil {
		return "", e
	}

	if strings.HasPrefix(v, "secp256k1") {
		x, y := secp256k1.S256().ScalarBaseMult(priv)
		pubKey = secp256k1.CompressPubkey(x, y)
		pubKeyStr := hexutil.Encode(pubKey)
		insecureHolderSecp256k1[pubKeyStr] = priv

		return pubKeyStr, nil
	} else if strings.HasPrefix(v, "ed25519") {
		pub := ed25519.NewKeyFromSeed(priv).Public()
		pubKey, _ = pub.([]byte)
		pubKeyStr := hexutil.Encode(pubKey)
		insecureHolderEd25519[pubKeyStr] = priv

		return pubKeyStr, nil
	} else {
		return "", errors.New("upsupported version " + version)
	}
}

func generateEphemeralKeyPair(version, signerPubkey string) (compressedPub string, err error) {
	priv, _ := generatePrivateKey()
	pubStr, err := derivePublicKey(version, hexutil.Encode(priv))
	if err != nil {
		return "", err
	}

	if len(signerPubkey) > 0 {
		v := strings.ToLower(version)
		var sig []byte

		if strings.HasPrefix(v, "secp256k1") {
			signer := insecureHolderSecp256k1[pubStr] // assuming we already have the signer private key -- this is NOT production code
			if signer == nil {
				return "", errors.New("no signer found for " + signerPubkey)
			}
			sig, err = secp256k1.Sign([]byte(pubStr), signer)
		} else if strings.HasPrefix(v, "ed25519") {
			signer := insecureHolderEd25519[pubStr]
			if signer == nil {
				return "", errors.New("no signer found for " + signerPubkey)
			}
			sig, err = signer.Sign(rand.Reader, []byte(pubStr), crypto.Hash(0))
		}

		if err != nil {
			return "", err
		}

		pubStr = pubStr + hexutil.Encode(sig)[2:]
	}

	return pubStr, nil
}

func generateWalletEntry(privateKey []byte) string {
	x, y := secp256k1.S256().ScalarBaseMult(privateKey)
	addr := ecrypto.Keccak256(x.Bytes(), y.Bytes())[12:32]
	account := hexutil.Encode(addr)
	inseaureWallet[account] = privateKey
	fmt.Println("putting address into wallet: " + account)
	return account
}

func wrapPrivateKey(version, R, signerPubKey string, oob, salt []byte, account string) (string, error) {
	sk := inseaureWallet[account]
	if sk == nil {
		return "", errors.New("private key not found for account: " + account)
	}

	// verify signature to R
	// verify signerPubKey TODO

	s, _ := generatePrivateKey()
	S, _ := derivePublicKey(version, hexutil.Encode(s))

	v := strings.ToLower(version)
	RBytes, _ := hexutil.Decode(R)
	var sharedSecret []byte

	if strings.HasPrefix(v, "secp256k1") {
		Rx, Ry := secp256k1.DecompressPubkey(RBytes)
		SSx, SSy := secp256k1.S256().ScalarMult(Rx, Ry, s)
		sharedSecret = make([]byte, 64)
		SSx.FillBytes(sharedSecret[:32])
		SSy.FillBytes(sharedSecret[32:])
	} else if strings.HasPrefix(v, "ed25519") {
		sharedSecret, _ = curve25519.X25519(RBytes, s)
	} else {
		return "", errors.New("unsupported version: " + version)
	}

	reader := hkdf.New(sha256.New, sharedSecret, salt, oob)
	var cipher string
	var err error = nil

	if strings.Contains(v, "aes-128-gcm") {
		cipher, err = encryptAesGcm(16, sk, reader)
	} else if strings.Contains(v, "aes-256-gcm") {
		cipher, err = encryptAesGcm(32, sk, reader)
	} else if strings.Contains(v, "chacha20-poly1305") {
		cipher, err = encryptChaPoly(sk, reader)
	} else {
		return "", errors.New("unknown or unsupported cipher from " + version)
	}

	return S + cipher, err
}

func encryptAesGcm(keySize int, data []byte, keys io.Reader) (string, error) {
	skey := make([]byte, keySize)
	n, e := keys.Read(skey)

	if n < keySize || e != nil {
		return "", errors.New("error calculating symmetric key")
	}

	block, e := aes.NewCipher(skey)
	if e != nil {
		return "", e
	}

	aead, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}

	return aeadSeal(aead, keys, data)
}

func encryptChaPoly(data []byte, keys io.Reader) (string, error) {
	keySize := 32
	skey := make([]byte, keySize)
	n, e := keys.Read(skey)

	if n < keySize || e != nil {
		return "", errors.New("error calculating symmetric key")
	}

	aead, e := chacha20poly1305.New(skey)
	if e != nil {
		return "", e
	}

	return aeadSeal(aead, keys, data)
}

func aeadSeal(aead cipher.AEAD, keys io.Reader, data []byte) (string, error) {
	ivSize := aead.NonceSize()
	IV := make([]byte, ivSize)
	n, e := keys.Read(IV)
	if n < ivSize || e != nil {
		return "", errors.New("error calculate the nonce")
	}

	dst := aead.Seal(nil, IV, data, nil)

	return hexutil.Encode(dst)[2:], nil
}

func intakePrivateKey(version, R string, oob, salt []byte, data string) (string, error) {
	dataBytes, _ := hexutil.Decode(data)

	v := strings.ToLower(version)
	var sharedSecret, cipherBytes []byte

	if strings.HasPrefix(v, "secp256k1") {
		SBytes := dataBytes[:33]
		cipherBytes = dataBytes[33:]

		Sx, Sy := secp256k1.DecompressPubkey(SBytes)
		r := insecureHolderSecp256k1[R]
		SSx, SSy := secp256k1.S256().ScalarMult(Sx, Sy, r)
		sharedSecret = make([]byte, 64)
		SSx.FillBytes(sharedSecret[:32])
		SSy.FillBytes(sharedSecret[32:])
	} else if strings.HasPrefix(v, "ed25519") {
		SBytes := dataBytes[:32]
		cipherBytes = dataBytes[32:]

		r := insecureHolderEd25519[R]
		sharedSecret, _ = curve25519.X25519(SBytes, r)
	} else {
		return "", errors.New("unsupported version: " + version)
	}

	reader := hkdf.New(sha256.New, sharedSecret, salt, oob)
	var cipher []byte
	var err error = nil

	if strings.Contains(v, "aes-128-gcm") {
		cipher, err = decryptAesGcm(16, cipherBytes, reader)
	} else if strings.Contains(v, "aes-256-gcm") {
		cipher, err = decryptAesGcm(32, cipherBytes, reader)
	} else if strings.Contains(v, "chacha20-poly1305") {
		cipher, err = decryptChaPoly(cipherBytes, reader)
	} else {
		return "", errors.New("unknown or unsupported cipher from " + version)
	}

	if err != nil {
		return "", err
	}

	// cipher should be a secp256k1 private key
	x, y := secp256k1.S256().ScalarBaseMult(cipher)
	addr := ecrypto.Keccak256(x.Bytes(), y.Bytes())[12:32]
	account := hexutil.Encode(addr)
	//fmt.Println("generated address from decrypted private key: " + account)

	return account, nil
}

func decryptAesGcm(keySize int, data []byte, keys io.Reader) ([]byte, error) {
	skey := make([]byte, keySize)
	n, e := keys.Read(skey)

	if n < keySize || e != nil {
		return nil, errors.New("error calculating symmetric key")
	}

	block, e := aes.NewCipher(skey)
	if e != nil {
		return nil, e
	}

	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}

	return aeadOpen(aead, keys, data)
}

func decryptChaPoly(data []byte, keys io.Reader) ([]byte, error) {
	keySize := 32
	skey := make([]byte, keySize)
	n, e := keys.Read(skey)

	if n < keySize || e != nil {
		return nil, errors.New("error calculating symmetric key")
	}

	aead, e := chacha20poly1305.New(skey)
	if e != nil {
		return nil, e
	}

	return aeadOpen(aead, keys, data)
}

func aeadOpen(aead cipher.AEAD, keys io.Reader, data []byte) ([]byte, error) {
	ivSize := aead.NonceSize()
	IV := make([]byte, ivSize)
	n, e := keys.Read(IV)
	if n < ivSize || e != nil {
		return nil, errors.New("error calculate the nonce")
	}

	return aead.Open(nil, IV, data, nil)
}
