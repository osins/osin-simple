package simple

import (
	"regexp"
	"time"

	"github.com/openshift/osin"
)

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
)

func NewServerConfig() *SimpleConfig {
	return &SimpleConfig{
		ServerConfig: &osin.ServerConfig{
			AuthorizationExpiration:   250,
			AccessExpiration:          3600,
			TokenType:                 "Bearer",
			AllowedAuthorizeTypes:     osin.AllowedAuthorizeType{osin.CODE},
			AllowedAccessTypes:        osin.AllowedAccessType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN},
			ErrorStatusCode:           200,
			AllowClientSecretInParams: false,
			AllowGetAccessRequest:     false,
			RetainTokenAfterRefresh:   false,
		},
	}
}

// NewServer creates a new server instance
func NewSimpleServer(config *SimpleConfig) *SimpleServer {
	if config.AuthorizeTokenGen == nil {
		config.AuthorizeTokenGen = &osin.AuthorizeTokenGenDefault{}
	}

	if config.AccessTokenGen == nil {
		config.AccessTokenGen = &osin.AccessTokenGenDefault{}
	}

	if config.Logger == nil {
		config.Logger = &osin.LoggerDefault{}
	}

	return &SimpleServer{
		Config:            config.ServerConfig,
		Storage:           config.Storage,
		AuthorizeTokenGen: config.AuthorizeTokenGen,
		AccessTokenGen:    config.AccessTokenGen,
		Now:               time.Now,
		Logger:            config.Logger,
	}
}

// Server is an OAuth2 implementation
type SimpleServer struct {
	Config            *osin.ServerConfig
	Storage           osin.Storage
	AuthorizeTokenGen osin.AuthorizeTokenGen
	AccessTokenGen    osin.AccessTokenGen
	Now               func() time.Time
	Logger            osin.Logger
}

type SimpleConfig struct {
	*osin.ServerConfig
	Storage           osin.Storage
	AuthorizeTokenGen osin.AuthorizeTokenGen
	AccessTokenGen    osin.AccessTokenGen
	Logger            osin.Logger
}
