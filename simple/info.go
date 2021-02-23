package simple

import (
	"fmt"

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
	if err := s.validate(req); err != nil {
		return nil, err
	}

	return s.get(req)
}

func (s *info) validate(req *osin.InfoRequest) error {
	if req.Code == "" {
		return fmt.Errorf("bearer is nil")
	}

	if req.Code == "" {
		return fmt.Errorf("code is nil")
	}

	var err error

	// load access data
	req.AccessData, err = s.Server.Storage.LoadAccess(req.Code)
	if err != nil {
		return fmt.Errorf("failed to load access data")
	}
	if req.AccessData == nil {
		return fmt.Errorf("access data is nil")
	}
	if req.AccessData.Client == nil {
		return fmt.Errorf("access data client is nil")
	}
	if req.AccessData.Client.GetRedirectUri() == "" {
		return fmt.Errorf("access data client redirect uri is empty")
	}
	if req.AccessData.IsExpiredAt(s.Server.Now()) {
		return fmt.Errorf("access data is expired")
	}

	return nil
}

func (s *info) get(req *osin.InfoRequest) (*AccessResponseData, error) {
	ad, err := s.Server.Storage.LoadAccess(req.Code)

	return &AccessResponseData{
		AccessToken:  ad.AccessToken,
		RefreshToken: ad.RefreshToken,
		ExpiresIn:    ad.ExpiresIn,
		Scope:        ad.Scope,
		UserData:     ad.UserData,
	}, err
}
