package internal

import (
	"github.com/rotisserie/eris"
	"golang.org/x/crypto/bcrypt"
)

type HashServiceBcrypt struct {
	Cost int
}

func (hb *HashServiceBcrypt) Hash(val string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(val), hb.Cost)
	if err != nil {
		return "", eris.Wrap(err, "error hashing value")
	}

	return string(hash), nil
}

func (hb *HashServiceBcrypt) CheckHash(hash, val string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(val))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}

		return false, eris.Wrap(err, "error checking hash")
	}

	return true, nil
}
