package config

import "fmt"

var (
	ERROR_CLIENT_NOT_EXISTS      error = fmt.Errorf("client not exists.")
	ERROR_AUTHORIZE_CREATE_ERROR error = fmt.Errorf("authorize create error.")
)
