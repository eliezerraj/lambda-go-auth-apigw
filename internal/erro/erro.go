package erro

import (
	"errors"

)

var (
	ErrStatusUnauthorized = errors.New("Unauthorized")
	ErrTokenExpired = errors.New("Token expired")
	ErrOpenDatabase 		= errors.New("Open Database error")
	ErrQuery 				= errors.New("Query error")
	ErrPreparedQuery 		= errors.New("Prepare dynamo query erro")
	ErrUnmarshal			= errors.New("Erro Unmarshall")
	ErrNotFound 			= errors.New("Data not found")
)