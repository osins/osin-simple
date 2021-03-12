package response

type AuthorizeResponse struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	Scope       string `json:"scope"`
	ExpiresIn   int32  `json:"expires_in"`
	RedirectUri string `json:"redirect_uri"`
}
