package util

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
)

const CODE_VERIFIER_RULE = "^[a-zA-Z0-9~._-]{16,128}$"

func NewCodeVerifier(v string) CodeVerifier {
	return &codeVerifier{
		BaseString: v,
	}
}

type CodeVerifier interface {
	Validate() (bool, error)
	CodeChallenge(t PKCEType) (string, error)
	Plain() (string, error)
	Sha256() (string, error)
}

type codeVerifier struct {
	BaseString string
}

func (s *codeVerifier) Validate() (bool, error) {
	if s == nil {
		return false, fmt.Errorf("base string is null.")
	}

	if regexp.MustCompile(CODE_VERIFIER_RULE).MatchString(s.BaseString) {
		return true, nil
	}

	return false, fmt.Errorf("code verifier validate error: %s\nbase string: %s", CODE_VERIFIER_RULE, s.BaseString)
}

func (s *codeVerifier) CodeChallenge(t PKCEType) (string, error) {
	if t == PKCE_PLAIN {
		return s.Plain()
	}

	return s.Sha256()
}

func (s *codeVerifier) Plain() (string, error) {
	if _, err := s.Validate(); err != nil {
		return "", err
	}

	return s.BaseString, nil
}

func (s *codeVerifier) Sha256() (string, error) {
	if _, err := s.Validate(); err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(s.BaseString))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
