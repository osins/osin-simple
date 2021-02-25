package simple

import (
	"github.com/openshift/osin"
)

func NewInfo(s *SimpleServer) Info {
	return &info{
		Server: s,
	}
}

type Info interface {
	Info(req *osin.InfoRequest) (*AccessResponseData, error)
}

type info struct {
	Server *SimpleServer
}

func (s *info) Info(req *osin.InfoRequest) (*AccessResponseData, error) {
	if err := s.requestValidate(req).Validate(); err != nil {
		return nil, err
	}

	return s.get(req)
}

func (s *info) requestValidate(req *osin.InfoRequest) ValidateRequest {
	return &infoRequestValidate{
		server: s.Server,
		req:    req,
	}
}

func (s *info) get(req *osin.InfoRequest) (*AccessResponseData, error) {
	ad, err := s.Server.Storage.LoadAccess(req.Code)

	return &AccessResponseData{
		AccessToken:  ad.AccessToken,
		RefreshToken: ad.RefreshToken,
		ExpiresIn:    ad.ExpiresIn,
		TokenType:    s.Server.Config.TokenType,
		Raw:          ad.UserData,
	}, err
}
