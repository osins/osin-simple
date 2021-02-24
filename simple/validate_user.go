package simple

type ValidateUser interface {
	Vaildate(code string, password string) error
}
