package credentials

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const (
	HashVersionBcrypt = "bcrypt"
)

// HashPassword hashes a plaintext password using bcrypt.
func HashPassword(password string) (hash string, version string, err error) {
	if len(password) < 8 {
		return "", "", errors.New("password too short")
	}

	bytes, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return "", "", err
	}

	return string(bytes), HashVersionBcrypt, nil
}

// VerifyPassword compares plaintext password with stored hash.
func VerifyPassword(hash string, password string) error {
	return bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(password),
	)
}
