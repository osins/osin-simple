package simple

import (
	"fmt"

	"github.com/openshift/osin"
)

func NewAccess(s *SimpleServer) SimpleAccess {
	return &simpleAccess{
		Server: s,
	}
}

type SimpleAccess interface {
	Access(req *osin.AccessRequest) (*AccessResponseData, error)
	GenAccessData(req *osin.AccessRequest) (*osin.AccessData, error)
}

type simpleAccess struct {
	Server *SimpleServer
}

func (acc *simpleAccess) Access(req *osin.AccessRequest) (*AccessResponseData, error) {
	if err := acc.requestValidate(req).Validate(); err != nil {
		return nil, fmt.Errorf("access type(%s), error: %s", req.Type, err.Error())
	}

	req.Authorized = true
	ad, createErr := acc.GenAccessData(req)
	if createErr != nil {
		return nil, createErr
	}

	return &AccessResponseData{
		AccessToken:  ad.AccessToken,
		RefreshToken: ad.RefreshToken,
		ExpiresIn:    ad.ExpiresIn,
		Scope:        ad.Scope,
		UserData:     ad.UserData,
	}, nil
}

func (acc *simpleAccess) GenAccessData(req *osin.AccessRequest) (*osin.AccessData, error) {
	var err error

	// generate access token
	ret := &osin.AccessData{
		Client:        req.Client,
		AuthorizeData: req.AuthorizeData,
		AccessData:    req.AccessData,
		RedirectUri:   req.RedirectUri,
		UserData:      req.UserData,
		Scope:         req.Scope,
		ExpiresIn:     acc.Server.Config.AccessExpiration,
		CreatedAt:     acc.Server.Now(),
	}

	// generate access token
	ret.AccessToken, ret.RefreshToken, err = acc.Server.AccessTokenGen.GenerateAccessToken(ret, true)
	if err != nil {
		return nil, fmt.Errorf("error generating token")
	}

	if req.AccessData != nil && ret.AccessToken == req.AccessData.AccessToken {
		return ret, nil
	}

	// save access token
	if err = acc.Server.Storage.SaveAccess(ret); err != nil {
		return nil, fmt.Errorf("error saving access token")
	}

	acc.removeOldData(req, ret)

	return ret, nil
}

func (acc *simpleAccess) removeOldData(old *osin.AccessRequest, new *osin.AccessData) {
	s := acc.Server
	// remove authorization token
	if old.AuthorizeData != nil && len(old.AuthorizeData.Code) > 0 {
		s.Storage.RemoveAuthorize(old.AuthorizeData.Code)
	}

	// remove previous access token
	if old.AccessData != nil && !s.Config.RetainTokenAfterRefresh {
		if old.AccessData.RefreshToken != new.RefreshToken && len(old.AccessData.RefreshToken) > 0 {
			s.Storage.RemoveRefresh(old.AccessData.RefreshToken)
		}

		if old.AccessData.AccessToken != new.AccessToken && len(old.AccessData.AccessToken) > 0 {
			s.Storage.RemoveAccess(old.AccessData.AccessToken)
		}
	}
}

func (s *simpleAccess) requestValidate(req *osin.AccessRequest) ValidateRequest {
	return &accessRequestValidate{
		server: s.Server,
		req:    req,
	}
}
