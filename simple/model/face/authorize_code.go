package face

import (
	"github.com/osins/osin-simple/simple/request"
	"github.com/osins/osin-simple/simple/util"
	"github.com/pborman/uuid"
)

type AuthorizeCode interface {
	GenerateCode(req *request.AuthorizeRequest) (accesstoken string, err error)
}

// AuthorizeTokenGenDefault is the default authorization token generator
type AuthorizeCodeDefault struct {
}

// GenerateAuthorizeToken generates a base64-encoded UUID code
func (a *AuthorizeCodeDefault) GenerateCode(req *request.AuthorizeRequest) (token string, err error) {
	return util.NewCodeVerifier(uuid.NewUUID().String()).Sha256()
}
