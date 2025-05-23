package access

import (
	"net/http"

	"github.com/cccteam/ccc/resource"
	"github.com/go-playground/validator/v10"
)

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

type LogHandler func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc

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

// NewDecoder returns an httpio.Decoder to simplify the validator call to a single location
func NewDecoder[T any](a *HandlerClient) *resource.StructDecoder[T] {
	decoder, err := resource.NewStructDecoder[T]()
	if err != nil {
		panic(err)
	}

	return decoder.WithValidator(a.validate)
}
