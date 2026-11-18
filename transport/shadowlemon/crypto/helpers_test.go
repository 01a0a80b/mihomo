package shadowlemoncrypto

import (
	"crypto/ecdh"
	"crypto/sha256"
	"hash"
	"os"
)

func newSHA256() hash.Hash { return sha256.New() }

func lookupEnv(key string) (string, bool) { return os.LookupEnv(key) }

func setEnv(key, value string) { _ = os.Setenv(key, value) }

func unsetEnv(key string) { _ = os.Unsetenv(key) }

// ecdhFromPrivate derives the X25519 public key from private bytes, for
// checking against the RFC 7748 vector.
func ecdhFromPrivate(priv []byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}
