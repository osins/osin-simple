package simple

type UserStorage interface {
	GetId(code string, password string) (string, error)
	BindToken(token string, userId string) error
	GetUser(userId string) (interface{}, error)
}
