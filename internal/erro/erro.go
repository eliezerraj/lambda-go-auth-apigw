package erro

import (
	"errors"

)

var (
	ErrStatusUnauthorized = errors.New("Unauthorized")
	ErrTokenExpired = errors.New("Token expired")
)