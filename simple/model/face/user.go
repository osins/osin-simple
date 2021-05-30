package face

type User interface {
	GetId() string
	GetUsername() string
	GetPassword() []byte
	GetSalt() []byte
	GetEmail() string
	GetMobile() string
}
