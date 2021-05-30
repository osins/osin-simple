package face

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func NewPasswordDefaultGen() PasswordGen {
	return &password{
		Iter:   4096,
		KeyLen: 32,
	}
}

type PasswordGen interface {
	Salt() ([]byte, error)
	Generate(key []byte, salt []byte) []byte
	Compare(password string, salt []byte, data []byte) bool
}

type password struct {
	Iter   int
	KeyLen int
}

func (s *password) Salt() (salt []byte, err error) {
	salt = make([]byte, 8)
	// http://www.ietf.org/rfc/rfc2898.txt
	// Salt.
	if _, err = rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

func (s *password) Generate(key []byte, salt []byte) []byte {
	return pbkdf2.Key(key, salt, s.Iter, s.KeyLen, sha256.New)
}

func (s *password) Compare(password string, salt []byte, data []byte) bool {
	code := pbkdf2.Key(
		[]byte(password),
		salt,
		s.Iter,
		s.KeyLen,
		sha256.New,
	)

	eq := bytes.Equal(code, data)

	fmt.Printf("\npassword compare:\n%v\n%v\neq:%v\n", code, data, eq)

	return eq
}
