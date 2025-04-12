package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func encrypt(inputMessage InputMessage, config Config) (EncryptedMessage, error) {
	senderPriv, err := loadKeyFromFile(config.SelfKeyConfig.Private)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error loading sender private key: %v", err)
	}

	symKey := make([]byte, 32)
	rand.Read(symKey)

	ciphertext, nonce, err := encryptSymmetric([]byte(inputMessage.RawText), symKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error encrypting message: %v", err)
	}

	encryptedKeys := make(map[string]string)
	for _, user := range inputMessage.Recipients {
		pubPath := getUserPublicKey(config.ExternalKeysDir, user)
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
		encryptedKeys[user] = base64.StdEncoding.EncodeToString(append(encNonce, encKey...))
	}

	sig, err := signMessage(ciphertext, config.SelfKeyConfig.SigningPrivate)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error signing message: %v", err)
	}

	signingPub, err := loadKeyFromFile(config.SelfKeyConfig.SigningPublic)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error loading signing public key: %v", err)
	}

	outputMsg := EncryptedMessage{
		Ciphertext:       base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		EncryptedKeys:    encryptedKeys,
		Signature:        base64.StdEncoding.EncodeToString(sig),
		SigningPublicKey: base64.StdEncoding.EncodeToString(signingPub),
		Sender:           config.UserID,
	}
	return outputMsg, nil
}

func decrypt(msg EncryptedMessage, config Config) (DecryptedMessage, error) {
	if msg.Sender == config.UserID {
		return DecryptedMessage{}, fmt.Errorf("cannot decrypt message sent by self")
	}

	priv, err := loadKeyFromFile(config.SelfKeyConfig.Private)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error loading private key: %v", err)
	}

	senderPubPath := getUserPublicKey(config.ExternalKeysDir, msg.Sender)
	senderPub, err := loadKeyFromFile(senderPubPath)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error loading sender public key: %v", err)
	}

	sharedKey, err := deriveSharedKey(priv, senderPub)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error deriving shared key: %v", err)
	}

	encKeyFull, err := base64.StdEncoding.DecodeString(msg.EncryptedKeys[config.UserID])
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decoding encrypted key: %v", err)
	}
	encNonce := encKeyFull[:chacha20poly1305.NonceSizeX]
	encKey := encKeyFull[chacha20poly1305.NonceSizeX:]

	symKey, err := decryptSymmetric(encKey, sharedKey, encNonce)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("error decrypting symmetric key: %v", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(msg.Nonce)
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
		Author:  msg.Sender,
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

func createSigningKeypair(selfKeyConfig SelfKeyConfig) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating Ed25519 keypair: %v", err)
	}
	err = saveKeyToFile(selfKeyConfig.SigningPrivate, priv)
	if err != nil {
		return err
	}
	err = saveKeyToFile(selfKeyConfig.SigningPublic, pub)
	if err != nil {
		return err
	}
	return nil
}

func createKeypair(selfKeyConfig SelfKeyConfig) error {
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("error generating key pair: %v", err)
	}
	err = saveKeyToFile(selfKeyConfig.Private, priv)
	if err != nil {
		return err
	}
	err = saveKeyToFile(selfKeyConfig.Public, pub)
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
