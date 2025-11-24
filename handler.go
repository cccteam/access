package access

import (
	"net/http"

	"github.com/cccteam/ccc/resource"
	"github.com/go-playground/validator/v10"
)

// Handlers provides HTTP handlers for managing user roles.
type Handlers interface {
	AddRole() http.HandlerFunc
	AddRolePermissions() http.HandlerFunc
	AddRoleUsers() http.HandlerFunc
	DeleteRole() http.HandlerFunc
	DeleteRolePermissions() http.HandlerFunc
	DeleteRoleUsers() http.HandlerFunc
	RolePermissions() http.HandlerFunc
	Roles() http.HandlerFunc
	RoleUsers() http.HandlerFunc
	User() http.HandlerFunc
	Users() http.HandlerFunc
}

// LogHandler wraps handlers with logging. Converts error-returning handler to http.HandlerFunc.
type LogHandler func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc

// HandlerClient implements Handlers for access management.
type HandlerClient struct {
	manager  UserManager
	validate *validator.Validate
	handler  LogHandler
}

var _ Handlers = &HandlerClient{}

func newHandler(client *Client, validate *validator.Validate, logHandler LogHandler) *HandlerClient {
	return &HandlerClient{
		manager:  client.UserManager(),
		validate: validate,
		handler:  logHandler,
	}
}

// NewDecoder creates a struct decoder with validation for HTTP requests. Panics on error.
func NewDecoder[T any](a *HandlerClient) *resource.StructDecoder[T] {
	decoder, err := resource.NewStructDecoder[T]()
	if err != nil {
		panic(err)
	}

	return decoder.WithValidator(a.validate)
}
