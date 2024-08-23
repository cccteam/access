package access

import (
	"net/http"

	"github.com/cccteam/httpio"
	"github.com/go-playground/validator/v10"
)

type Handlers interface {
	Users() http.HandlerFunc
	User() http.HandlerFunc
	AddRole() http.HandlerFunc
	AddRolePermissions() http.HandlerFunc
	AddRoleUsers() http.HandlerFunc
	DeleteRoleUsers() http.HandlerFunc
	DeleteRolePermissions() http.HandlerFunc
	Roles() http.HandlerFunc
	RoleUsers() http.HandlerFunc
	RolePermissions() http.HandlerFunc
	DeleteRole() http.HandlerFunc
}

type LogHandler func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc

type HandlerClient struct {
	manager  Manager
	validate *validator.Validate
	handler  LogHandler
}

var _ Handlers = &HandlerClient{}

func newHandler(client *Client, validate *validator.Validate, logHandler LogHandler) *HandlerClient {
	return &HandlerClient{
		manager:  client,
		validate: validate,
		handler:  logHandler,
	}
}

// NewDecoder returns an httpio.Decoder to simplify the validator call to a single location
func (a *HandlerClient) NewDecoder(req *http.Request) *httpio.Decoder {
	return httpio.NewDecoder(req, a.validate.Struct)
}
