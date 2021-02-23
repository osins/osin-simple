package simple

import (
	"fmt"
	"strings"
)

func NewToken() Token {
	return &token{}
}

type Token interface {
	AuthorizationToCode(authorization string) (string, error)
}

type token struct {
}

func (s *token) AuthorizationToCode(authorization string) (string, error) {
	if authorization == "" {
		return "", fmt.Errorf("authorization string is nil.")
	}

	str := strings.SplitN(authorization, " ", 2)
	if len(str) != 2 || strings.ToLower(str[0]) != "bearer" || strings.ToLower(str[0]) != "bearer" {
		return "", fmt.Errorf("authorization string not bearer.")
	}

	return str[1], nil
}
