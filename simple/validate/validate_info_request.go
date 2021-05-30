package validate

import (
	"fmt"

	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/model/face"
	"github.com/osins/osin-simple/simple/request"
)

type InfoRequestValidate struct {
	Conf   *config.SimpleConfig
	Req    *request.InfoRequest
	Access face.Access
	Client face.Client
	User   face.User
}

func (val *InfoRequestValidate) Validate() (err error) {
	if val.Req.Code == "" {
		return fmt.Errorf("bearer is nil")
	}

	if _, err := val.Conf.AccessTokenGen.VerifyToken(val.Req.Code); err != nil {
		val.Conf.Logger.Error("verify token faild, code: %s, access: %v", val.Req.Code, val.Access)
		return err
	}

	// load access data
	val.Access, err = val.Conf.Storage.Access.Get(val.Req.Code)
	if err != nil {
		return fmt.Errorf("failed to load access data")
	}

	if val.Access == nil {
		return fmt.Errorf("access data is nil")
	}

	if val.Access.IsExpiredAt(val.Conf.Now()) {
		return fmt.Errorf("access data is expired")
	}

	if val.Access.GetClient() == nil {
		return fmt.Errorf("access data client is nil")
	}

	return nil
}
