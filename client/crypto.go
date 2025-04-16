package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func encrypt(inputMessage InputMessage, config Config) (EncryptedMessage, error) {
	senderPriv, err := loadKeyFromFile(fmt.Sprintf("%s/private.key", config.Keys.PrivateKeys))
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error loading sender private key: %v", err)
	}

	if len(inputMessage.Recipients) == 0 {
		return EncryptedMessage{}, fmt.Errorf("message has no recipients")
	}

	symKey := make([]byte, 32)
	rand.Read(symKey)

	ciphertext, nonce, err := encryptSymmetric([]byte(inputMessage.RawText), symKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error encrypting message: %v", err)
	}

	encryptedKeys := make(map[string]string)
	for _, user := range inputMessage.Recipients {
		pubPath := getUserPublicKey(config.Keys.ExternalKeys, user)
		pub, err := loadKeyFromFile(pubPath)
		if err != nil {
			return EncryptedMessage{}, fmt.Errorf("error loading recipient public key: %v", err)
		}
		sharedKey, err := deriveSharedKey(senderPriv, pub)
		if err != nil {
			return EncryptedMessage{}, fmt.Errorf("error deriving shared key: %v", err)
		}
		encKey, encNonce, err := encryptSymmetric(symKey, sharedKey)
		if err != nil {
			return EncryptedMessage{}, fmt.Errorf("error encrypting symmetric key: %v", err)
		}
		userHash := hashString(user)

		encryptedKeys[userHash] = base64.StdEncoding.EncodeToString(append(encNonce, encKey...))
	}

	sig, err := signMessage(ciphertext, fmt.Sprintf("%s/signing_private.key", config.Keys.PrivateKeys))
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error signing message: %v", err)
	}

	signingPub, err := loadKeyFromFile(fmt.Sprintf("%s/signing_public.key", config.Keys.PrivateKeys))
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error loading signing public key: %v", err)
	}

	outputMsg := EncryptedMessage{
		Ciphertext:       base64.StdEncoding.EncodeToString(ciphertext),
		Verify:           base64.StdEncoding.EncodeToString(nonce),
		EncryptedKeys:    encryptedKeys,
		Signature:        base64.StdEncoding.EncodeToString(sig),
		SigningPublicKey: base64.StdEncoding.EncodeToString(signingPub),
		Sender:           hashString(config.UserID),
	}
	return outputMsg, nil
}

func decrypt(msg EncryptedMessage, config Config) (DecryptedMessage, error) {
	hashedUsername := hashString(config.UserID)
	if msg.Sender == hashedUsername {
		return DecryptedMessage{}, fmt.Errorf("cannot decrypt message sent by self")
	}

	if len(msg.EncryptedKeys) == 0 {
		return DecryptedMessage{}, fmt.Errorf("message contains no keys")
	}

	if _, ok := msg.EncryptedKeys[hashedUsername]; !ok {
		return DecryptedMessage{}, fmt.Errorf("message does not contain key for this user")
	}

	senderUsername, err := getUsernameFromHash(msg.Sender, config)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("unable to determine sender's username: %v", err)
	}

	priv, err := loadKeyFromFile(fmt.Sprintf("%s/private.key", config.Keys.PrivateKeys))
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error loading private key: %v", err)
	}

	senderPubPath := getUserPublicKey(config.Keys.ExternalKeys, senderUsername)
	senderPub, err := loadKeyFromFile(senderPubPath)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error loading sender public key: %v", err)
	}

	sharedKey, err := deriveSharedKey(priv, senderPub)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error deriving shared key: %v", err)
	}

	encKeyFull, err := base64.StdEncoding.DecodeString(msg.EncryptedKeys[hashedUsername])
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decoding encrypted key: %v", err)
	}
	encNonce := encKeyFull[:chacha20poly1305.NonceSizeX]
	encKey := encKeyFull[chacha20poly1305.NonceSizeX:]

	symKey, err := decryptSymmetric(encKey, sharedKey, encNonce)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decrypting symmetric key: %v", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(msg.Verify)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decoding nonce: %v", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(msg.Ciphertext)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decoding ciphertext: %v", err)
	}

	sig, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decoding signature: %v", err)
	}

	signingPub, err := base64.StdEncoding.DecodeString(msg.SigningPublicKey)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decoding signing public key: %v", err)
	}

	if !ed25519.Verify(signingPub, ciphertext, sig) {
		return DecryptedMessage{}, fmt.Errorf("signature verification failed")
	}

	plaintext, err := decryptSymmetric(ciphertext, symKey, nonce)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decrypting message: %v", err)
	}

	decryptedMessage := DecryptedMessage{
		RawText: string(plaintext),
		Author:  senderUsername,
	}

	return decryptedMessage, nil
}

func generateX25519KeyPair() ([]byte, []byte, error) {
	priv := make([]byte, 32)
	_, err := rand.Read(priv)
	if err != nil {
		return nil, nil, err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}

func createSigningKeypair(keysDir string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating Ed25519 keypair: %v", err)
	}
	err = saveKeyToFile(fmt.Sprintf("%s/signing_private.key", keysDir), priv)
	if err != nil {
		return err
	}
	err = saveKeyToFile(fmt.Sprintf("%s/signing_public.key", keysDir), pub)
	if err != nil {
		return err
	}
	return nil
}

func createKeypair(keyDir string) error {
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("error generating key pair: %v", err)
	}
	err = saveKeyToFile(fmt.Sprintf("%s/private.key", keyDir), priv)
	if err != nil {
		return err
	}
	err = saveKeyToFile(fmt.Sprintf("%s/public.key", keyDir), pub)
	if err != nil {
		return err
	}
	return nil
}

func deriveSharedKey(priv, pub []byte) ([]byte, error) {
	return curve25519.X25519(priv, pub)
}

func encryptSymmetric(message, key []byte) (ciphertext, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	ciphertext = aead.Seal(nil, nonce, message, nil)
	return ciphertext, nonce, nil
}

func decryptSymmetric(ciphertext, key, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func signMessage(message []byte, privPath string) ([]byte, error) {
	priv, err := loadKeyFromFile(privPath)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, message), nil
}
