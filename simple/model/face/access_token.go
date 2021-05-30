package face

import (
	"github.com/osins/osin-simple/simple/util"
	"github.com/pborman/uuid"
)

func NewAccessDefaultTokenGen() AccessTokenGen {
	return &accessDefaultTokenGen{}
}

type AccessTokenGen interface {
	GenerateAccessToken(data Access, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
	VerifyToken(code string) (Access, error)
}

// AccessTokenGenDefault is the default authorization token generator
type accessDefaultTokenGen struct {
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *accessDefaultTokenGen) GenerateAccessToken(data Access, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	accesstoken, err = util.NewCodeVerifier(string(uuid.NewUUID())).Sha256()

	if generaterefresh {
		refreshtoken, err = util.NewCodeVerifier(string(uuid.NewUUID())).Sha256()
	}

	return
}

func (a *accessDefaultTokenGen) VerifyToken(code string) (Access, error) {
	return nil, nil
}
