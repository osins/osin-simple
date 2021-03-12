package simple

import (
	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/request"
	"github.com/osins/osin-simple/simple/response"
	"github.com/osins/osin-simple/simple/validate"
)

func NewInfo(s *SimpleServer) Info {
	return &info{
		Conf: s.Config,
	}
}

type Info interface {
	Info(req *request.InfoRequest) (*response.AccessResponse, error)
}

type info struct {
	Conf *config.SimpleConfig
}

func (s *info) Info(req *request.InfoRequest) (*response.AccessResponse, error) {
	if err := s.requestValidate(req).Validate(); err != nil {
		return nil, err
	}

	return s.get(req)
}

func (s *info) requestValidate(req *request.InfoRequest) validate.ValidateRequest {
	return &validate.InfoRequestValidate{
		Conf: s.Conf,
		Req:  req,
	}
}

func (s *info) get(req *request.InfoRequest) (*response.AccessResponse, error) {
	acc, err := s.Conf.Storage.Access.Get(req.Code)

	return &response.AccessResponse{
		AccessToken:  acc.GetAccessToken(),
		RefreshToken: acc.GetRefreshToken(),
		ExpiresIn:    acc.GetExpiresIn(),
		User:         acc.GetUser(),
	}, err
}
