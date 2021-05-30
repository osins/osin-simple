package face

import (
	"github.com/osins/osin-simple/simple/request"
	"github.com/osins/osin-simple/simple/util"
	"github.com/pborman/uuid"
)

func NewAuthorizeDefaultCodeGen() AuthorizeCodeGen {
	return &authorizationCodeGen{}
}

type AuthorizeCodeGen interface {
	GenerateCode(req *request.AuthorizeRequest) (accesstoken string, err error)
}

// AuthorizeTokenGenDefault is the default authorization token generator
type authorizationCodeGen struct {
}

// GenerateAuthorizeToken generates a base64-encoded UUID code
func (a *authorizationCodeGen) GenerateCode(req *request.AuthorizeRequest) (token string, err error) {
	return util.NewCodeVerifier(uuid.NewUUID().String()).Sha256()
}
