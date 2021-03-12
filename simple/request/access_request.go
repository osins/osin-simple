package request

// Authorize request information
type AccessRequest struct {
	Username  string
	Password  string
	Code      string
	GrantType AccessGrantType

	ClientId     string
	ClientSecret string

	Scope string
	State string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default.
	// If type = TOKEN, this expiration will be for the ACCESS token.
	Expiration int32

	// Optional code_verifier as described in rfc7636
	CodeVerifier string

	// Optional code_verifier as described in rfc7636
	CodeVerifierMethod string
}
