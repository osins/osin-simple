package util

type PKCEType string

const (
	PKCE_PLAIN PKCEType = "plain"
	PKCE_S256  PKCEType = "S256"
)
