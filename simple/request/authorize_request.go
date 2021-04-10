package request

// Authorize request information
type AuthorizeRequest struct {
	ClientId     string
	ClientSecret string
	ResponseType AuthorizeResponseType
	RedirectUri  string
	Scope        string
	State        string
	Username     string
	Password     string
	EMail        string
	Mobile       string

	// Optional code_challenge as described in rfc7636
	CodeChallenge string

	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}
