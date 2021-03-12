package simple

import (
	"time"

	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/log"
	"github.com/osins/osin-simple/simple/model/face"
)

// NewServer creates a new server instance
func NewSimpleServer(config *config.SimpleConfig) *SimpleServer {
	if config.AuthorizeCode == nil {
		config.AuthorizeCode = &face.AuthorizeCodeDefault{}
	}

	if config.AccessToken == nil {
		config.AccessToken = &face.AccessTokenDefault{}
	}

	if config.Logger == nil {
		config.Logger = &log.LoggerDefault{}
	}

	return &SimpleServer{
		Config:        config,
		AuthorizeCode: config.AuthorizeCode,
		AccessToken:   config.AccessToken,
		Now:           time.Now,
		Logger:        config.Logger,
	}
}

// Server is an OAuth2 implementation
type SimpleServer struct {
	Config        *config.SimpleConfig
	AuthorizeCode face.AuthorizeCode
	AccessToken   face.AccessToken
	Now           func() time.Time
	Logger        log.Logger
}
