package request

type AccessGrantType string

const (
	ACCESS_GRANT_AUTHORIZATION_CODE AccessGrantType = "authorization_code"
	ACCESS_GRANT_REFRESH_TOKEN      AccessGrantType = "refresh_token"
	ACCESS_GRANT_PASSWORD           AccessGrantType = "password"
	ACCESS_GRANT_CLIENT_CREDENTIALS AccessGrantType = "client_credentials"
	ACCESS_GRANT_ASSERTION          AccessGrantType = "assertion"
	ACCESS_GRANT_IMPLICIT           AccessGrantType = "__implicit"
)
