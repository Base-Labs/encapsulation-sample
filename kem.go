package encapsulation_sample

import (
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

// insecure and just for demo purposes
var inseaureWallet = map[string]([]byte){} // address -- private key mapping for Ethereum

var r, s, signer, trusted []byte

func init() {
	r, _ = hexutil.Decode("0x6f2dd2a7804705d2d536bee92221051865a639efa23f5ca7c810e77048253a79")
	s, _ = hexutil.Decode("0x28fa2db9f916e44fcc88370bedaf5eb3ec45632f040f4c1450c0f101e1e8bac8")
	signer, _ = hexutil.Decode("0xac304db075d1685284ba5e10c343f2324ee32df3394fc093c98932517d36e344")
	trusted, _ = hexutil.Decode("0xda6649d68fc03b807e444e0034b3b59ec60716212007d72c9ddbfd33e25d38d1")
}

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

		return pubKeyStr, nil
	} else if strings.HasPrefix(v, "curve25519") {
		// https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
		// not an actual public key
		pub := make([]byte, 32)
		curve25519.ScalarBaseMult((*[32]byte)(pub), (*[32]byte)(priv))
		pubKeyStr := hexutil.Encode(pub)

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
			// SHA256 first
			sum := sha256.Sum256([]byte(pubStr))
			sig, err = secp256k1.Sign(sum[:], signer)
			if err != nil {
				return "", err
			}

			sig = sig[:64]
		} else if strings.HasPrefix(v, "curve25519") {
			sig = ed25519.Sign(signer, []byte(pubStr))
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
	//fmt.Println("putting address into wallet: " + account)
	return account
}

func wrapPrivateKey(version, R, signerPubKey string, oob, salt []byte, account string) (string, error) {
	sk := inseaureWallet[account]
	if sk == nil {
		return "", errors.New("private key not found for account: " + account)
	}

	// verify signature to R
	// verify signerPubKey TODO

	//s, _ := generatePrivateKey() -- we use fixed value to generate test vectors
	S, _ := derivePublicKey(version, hexutil.Encode(s))

	v := strings.ToLower(version)
	RBytes, _ := hexutil.Decode(R)
	var sharedSecret []byte

	if strings.HasPrefix(v, "secp256k1") {
		if len(signerPubKey) > 0 && !verifySecp256k1(RBytes[:33], RBytes[33:], signerPubKey) {
			return "", errors.New("signature verification failed")
		}

		Rx, Ry := secp256k1.DecompressPubkey(RBytes[:33])
		if Rx == nil || Ry == nil {
			return "", errors.New("invalid public key: " + R[:68])
		}

		SSx, _ := secp256k1.S256().ScalarMult(Rx, Ry, s)
		sharedSecret = make([]byte, 32) // compact representation https://www.rfc-editor.org/rfc/rfc5903.html section 9
		SSx.FillBytes(sharedSecret)     // ensuring leading 00s if any
	} else if strings.HasPrefix(v, "curve25519") {
		if len(signerPubKey) > 0 && !verifyEd25519(RBytes[:32], RBytes[32:], signerPubKey) {
			return "", errors.New("signature verification failed")
		}

		sharedSecret, _ = curve25519.X25519(s, RBytes[:32])
	} else {
		return "", errors.New("unsupported version: " + version)
	}

	fmt.Println("shared secret in the sender side: " + hexutil.Encode(sharedSecret))

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

func verifySecp256k1(msg, sig []byte, signerPubKey string) bool {
	sum := sha256.Sum256(msg)
	signerPubBytes, _ := hexutil.Decode(signerPubKey)

	if len(signerPubBytes) > 33 {
		// signerPubKey is further signed, check if it is signed by trusted public key
	}

	return secp256k1.VerifySignature(signerPubBytes[:33], sum[:], sig) // the underlying library can handle compressed public key
}

func verifyEd25519(msg, sig []byte, signerPubKey string) bool {
	pub, _ := hexutil.Decode(signerPubKey)
	return ed25519.Verify(pub, msg, sig)
}

func encryptAesGcm(keySize int, data []byte, keys io.Reader) (string, error) {
	aead, err := prepAes(keySize, keys)
	if err != nil {
		return "", err
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

	fmt.Println("IV/nonce: " + hexutil.Encode(IV))

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
		if Sx == nil || Sy == nil {
			return "", errors.New("invalid public key: " + data[:68])
		}
		//r := insecureHolderSecp256k1[R[:68]]
		x, _ := secp256k1.S256().ScalarMult(Sx, Sy, r) // only x coordinate is needed

		sharedSecret = make([]byte, 32)
		sharedSecret = x.FillBytes(sharedSecret)
	} else if strings.HasPrefix(v, "curve25519") {
		SBytes := dataBytes[:32]
		cipherBytes = dataBytes[32:]

		sharedSecret, _ = curve25519.X25519(r, SBytes)
	} else {
		return "", errors.New("unsupported version: " + version)
	}

	fmt.Println("shared secret in the recipient side: " + hexutil.Encode(sharedSecret))

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
	aead, err := prepAes(keySize, keys)
	if err != nil {
		return nil, err
	}

	return aeadOpen(aead, keys, data)
}

func prepAes(keySize int, keys io.Reader) (cipher.AEAD, error) {
	skey := make([]byte, keySize)
	n, e := keys.Read(skey)

	if n < keySize || e != nil {
		return nil, errors.New("error calculating symmetric key")
	}

	fmt.Println("symmetric key: " + hexutil.Encode(skey))

	block, e := aes.NewCipher(skey)
	if e != nil {
		return nil, e
	}

	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return aead, nil
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

	fmt.Println("IV/nonce: " + hexutil.Encode(IV))

	return aead.Open(nil, IV, data, nil)
}
