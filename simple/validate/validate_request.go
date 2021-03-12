package validate

type ValidateRequest interface {
	Validate() error
}
