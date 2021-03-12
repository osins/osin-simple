package request

// AllowedAuthorizeType is a collection of allowed auth request types
type AllowedAuthorizeResponseType []AuthorizeResponseType

// Exists returns true if the auth type exists in the list
func (s AllowedAuthorizeResponseType) Exists(t AuthorizeResponseType) bool {
	for _, k := range s {
		if k == t {
			return true
		}
	}
	return false
}
