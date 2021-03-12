package face

type Client interface {
	GetId() string
	GetNeedLogin() bool
	GetRedirectUri() string
	GetSecret() string
	GetNeedRefresh() bool
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
}
