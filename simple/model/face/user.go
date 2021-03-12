package face

type User interface {
	GetId() string
	GetUsername() string
	GetPassword() string
	GetEmail() string
	GetMobile() string
}
