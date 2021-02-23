package simple

type AccessResponseData struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int32
	Scope        string
	UserData     interface{}
}
