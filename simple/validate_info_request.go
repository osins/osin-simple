package simple

import (
	"fmt"

	"github.com/openshift/osin"
)

type infoRequestValidate struct {
	server *SimpleServer
	req    *osin.InfoRequest
}

func (val *infoRequestValidate) Validate() error {
	if val.req.Code == "" {
		return fmt.Errorf("bearer is nil")
	}

	if val.req.Code == "" {
		return fmt.Errorf("code is nil")
	}

	var err error

	// load access data
	val.req.AccessData, err = val.server.Storage.LoadAccess(val.req.Code)
	if err != nil {
		return fmt.Errorf("failed to load access data")
	}

	if val.req.AccessData == nil {
		return fmt.Errorf("access data is nil")
	}

	if val.req.AccessData.Client == nil {
		return fmt.Errorf("access data client is nil")
	}

	if val.req.AccessData.IsExpiredAt(val.server.Now()) {
		return fmt.Errorf("access data is expired")
	}

	return nil
}
