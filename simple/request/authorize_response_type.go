package request

type AuthorizeResponseType string

const (
	AUTHORIZE_RESPONSE_CODE  AuthorizeResponseType = "code"
	AUTHORIZE_RESPONSE_LOGIN AuthorizeResponseType = "login"
	AUTHORIZE_RESPONSE_TOKEN AuthorizeResponseType = "token"
)
