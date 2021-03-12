package request

// AllowedAuthorizeType is a collection of allowed auth request types
type AllowedAccessGrantType []AccessGrantType

// Exists returns true if the auth type exists in the list
func (s AllowedAccessGrantType) Exists(t AccessGrantType) bool {
	for _, k := range s {
		if k == t {
			return true
		}
	}
	return false
}
