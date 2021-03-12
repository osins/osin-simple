package simple

import (
	"fmt"

	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/model/entity"
	"github.com/osins/osin-simple/simple/request"
	"github.com/osins/osin-simple/simple/response"
	"github.com/osins/osin-simple/simple/validate"
)

func NewAccess(s *SimpleServer) Access {
	return &access{
		Conf: s.Config,
	}
}

type Access interface {
	Access(req *request.AccessRequest) (*response.AccessResponse, error)
}

type access struct {
	Conf *config.SimpleConfig
}

func (acc *access) Access(req *request.AccessRequest) (res *response.AccessResponse, err error) {
	val := &validate.AccessRequestValidate{
		Conf: acc.Conf,
		Req:  req,
		Res:  &response.AccessResponse{},
	}

	if err = val.Validate(); err != nil {
		return nil, fmt.Errorf("access type(%s), error: %s", req.GrantType, err.Error())
	}

	err = acc.createAccessData(val)
	if err != nil {
		return nil, err
	}

	val.Res.User = val.User

	return val.Res, nil
}

func (acc *access) createAccessData(val *validate.AccessRequestValidate) (err error) {
	if val.Res == nil {
		val.Res = &response.AccessResponse{}
	}

	data := &entity.Access{}
	data.Client = val.Client
	data.ExpiresIn = val.Req.Expiration
	data.Scope = val.Req.Scope
	data.ClientId = val.Client.GetId()
	data.CreatedAt = acc.Conf.Now()

	if val.User != nil {
		val.Conf.Logger.Info("create access data\nuser: %v\nclient: %v", val.User, val.Client)
		data.User = val.User
		data.UserId = val.User.GetId()
	} else if data.Client.GetNeedLogin() {
		val.Conf.Logger.Error("create access data error, user not exists: %v", val)
		return fmt.Errorf("client user not exists.")
	}

	// generate access token
	data.AccessToken, data.RefreshToken, err = acc.Conf.AccessToken.GenerateAccessToken(data, val.Client.GetNeedRefresh())
	if err != nil {
		return fmt.Errorf("error generating token: %s", err.Error())
	}

	val.Res.AccessToken = data.AccessToken
	val.Res.RefreshToken = data.RefreshToken
	val.Res.ExpiresIn = acc.Conf.AccessExpiration

	// save access token
	if err = acc.Conf.Storage.Access.Create(data); err != nil {
		return fmt.Errorf("error saving access token: %s", err.Error())
	}

	if val.Req.GrantType == request.ACCESS_GRANT_PASSWORD && acc.Conf.Storage.User != nil {
		if err := acc.Conf.Storage.Access.BindUser(data.AccessToken, data.UserId); err != nil {
			return err
		}
	}

	if err := acc.removeOldData(val); err != nil {
		return fmt.Errorf("remove old access token or refresh token error: %s", err.Error())
	}

	return nil
}

func (acc *access) removeOldData(val *validate.AccessRequestValidate) error {
	switch val.Req.GrantType {
	case request.ACCESS_GRANT_AUTHORIZATION_CODE:
		if err := acc.Conf.Storage.Access.RemoveAuthorize(val.Req.Code); err != nil {
			return err
		}

		return nil
	case request.ACCESS_GRANT_REFRESH_TOKEN:
		if len(val.Req.Code) > 0 && val.Req.Code != val.Res.RefreshToken {
			if err := acc.Conf.Storage.Access.RemoveRefresh(val.Req.Code); err != nil {
				return err
			}
		}

		return nil
	case request.ACCESS_GRANT_PASSWORD:
		if len(val.Req.Code) > 0 {
			if err := acc.Conf.Storage.Access.RemoveAuthorize(val.Req.Code); err != nil {
				return err
			}
		}

		return nil
	}

	return nil
}
