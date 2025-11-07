// package access implements tools to manage access to resources. It is a wrapper around casbin using an rbac model.
package access


import "cloud.google.com/go/spanner"

const name = "github.com/cccteam/access"

var _ Access = (*SpannerStore)(nil)

// New creates a new user client
func New(client *spanner.Client, domains Domains) (Access, error) {
	return NewSpannerStore(client, domains), nil
}

