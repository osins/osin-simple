package face

import (
	"github.com/osins/osin-simple/simple/util"
	"github.com/pborman/uuid"
)

type AccessToken interface {
	GenerateAccessToken(data Access, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
	VerifyToken(code string) (Access, error)
}

// AccessTokenGenDefault is the default authorization token generator
type AccessTokenDefault struct {
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *AccessTokenDefault) GenerateAccessToken(data Access, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	accesstoken, err = util.NewCodeVerifier(string(uuid.NewUUID())).Sha256()

	if generaterefresh {
		refreshtoken, err = util.NewCodeVerifier(string(uuid.NewUUID())).Sha256()
	}

	return
}

func (a *AccessTokenDefault) VerifyToken(code string) (Access, error) {
	return nil, nil
}
