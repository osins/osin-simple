package simple

import (
	"fmt"

	"github.com/openshift/osin"
)

func NewSimpleAccess(s *SimpleServer) SimpleAccess {
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

func (acc *simpleAccess) Access(ar *osin.AccessRequest) (*AccessResponseData, error) {
	req := acc.accessRequestToRequestValidate(ar)
	if err := req.Validate(); err != nil {
		return nil, err
	}

	ar.Authorized = true
	ad, createErr := acc.GenAccessData(ar)
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
	s := acc.Server
	if !req.Authorized {
		return nil, fmt.Errorf("authorization failed")
	}

	var err error

	// generate access token
	ret := &osin.AccessData{
		Client:        req.Client,
		AuthorizeData: req.AuthorizeData,
		AccessData:    req.AccessData,
		RedirectUri:   req.RedirectUri,
		UserData:      req.UserData,
		Scope:         req.Scope,
		ExpiresIn:     s.Config.AccessExpiration,
		CreatedAt:     s.Now(),
	}

	// generate access token
	ret.AccessToken, ret.RefreshToken, err = s.AccessTokenGen.GenerateAccessToken(ret, req.GenerateRefresh)
	if err != nil || ret.AccessToken == req.AccessData.AccessToken || ret.RefreshToken == req.AccessData.RefreshToken {
		return nil, fmt.Errorf("error generating token")
	}

	// save access token
	if err = s.Storage.SaveAccess(ret); err != nil {
		return nil, fmt.Errorf("error saving access token")
	}

	acc.removeOldData(req, ret)

	return ret, nil
}

func (acc *simpleAccess) removeOldData(old *osin.AccessRequest, new *osin.AccessData) {
	s := acc.Server
	// remove authorization token
	if old.AuthorizeData != nil {
		s.Storage.RemoveAuthorize(old.AuthorizeData.Code)
	}

	// remove previous access token
	if old.AccessData != nil && !s.Config.RetainTokenAfterRefresh {
		if old.AccessData.RefreshToken != new.RefreshToken {
			s.Storage.RemoveRefresh(old.AccessData.RefreshToken)
		}

		if old.AccessData.AccessToken != new.AccessToken {
			s.Storage.RemoveAccess(old.AccessData.AccessToken)
		}
	}
}

func (s *simpleAccess) accessRequestToRequestValidate(req *osin.AccessRequest) ValidateRequest {
	return &accessRequestValidate{
		server: s.Server,
		req:    req,
	}
}
