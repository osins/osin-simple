package simple

import (
	"time"

	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/log"
	"github.com/osins/osin-simple/simple/model/face"
)

// NewServer creates a new server instance
func NewSimpleServer(config *config.SimpleConfig) *SimpleServer {
	if config.AuthorizeCodeGen == nil {
		config.AuthorizeCodeGen = face.NewAuthorizeDefaultCodeGen()
	}

	if config.AccessTokenGen == nil {
		config.AccessTokenGen = face.NewAccessDefaultTokenGen()
	}

	if config.PasswordGen == nil {
		config.PasswordGen = face.NewPasswordDefaultGen()
	}

	if config.Logger == nil {
		config.Logger = &log.LoggerDefault{}
	}

	return &SimpleServer{
		Config: config,
		Now:    time.Now,
		Logger: config.Logger,
	}
}

// Server is an OAuth2 implementation
type SimpleServer struct {
	Config *config.SimpleConfig
	Now    func() time.Time
	Logger log.Logger
}
