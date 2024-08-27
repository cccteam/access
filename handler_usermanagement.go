package access

import (
	"net/http"

	"github.com/cccteam/httpio"
	"go.opentelemetry.io/otel"
)

const (
	paramUser        httpio.ParamType = "user"
	paramGuarantorID httpio.ParamType = "guarantorId"
	paramRole        httpio.ParamType = "role"
)

// Users is the handler to get the list of users in the system
//
// Permissions Required: ViewUsers
func (a *HandlerClient) Users() http.HandlerFunc {
	type user struct {
		Name        string                  `json:"name"`
		Roles       map[Domain][]Role       `json:"roles"`
		Permissions map[Domain][]Permission `json:"permissions"`
	}

	type response []*user

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.Users()")
		defer span.End()

		userList, err := a.manager.Users(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		res := make(response, 0, len(userList))
		for _, u := range userList {
			res = append(res, (*user)(u))
		}

		return httpio.NewEncoder(w).Ok(res)
	})
}

// User is the handler to get a user
//
// Permissions Required: ViewUsers
func (a *HandlerClient) User() http.HandlerFunc {
	type response struct {
		Name        string                  `json:"name"`
		Roles       map[Domain][]Role       `json:"roles"`
		Permissions map[Domain][]Permission `json:"permissions"`
	}

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.User()")
		defer span.End()

		username := httpio.Param[string](r, paramUser)

		user, err := a.manager.User(ctx, User(username))
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok((*response)(user))
	})
}

// AddRole is the handler to add a new role to the system
//
// Permissions Required: AddRole
func (a *HandlerClient) AddRole() http.HandlerFunc {
	type request struct {
		RoleName Role `json:"roleName" validate:"min=1"`
	}

	type response struct {
		Role Role `json:"role"`
	}

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.AddRole()")
		defer span.End()

		req := &request{}
		if err := a.NewDecoder(r).Decode(req); err != nil {
			return httpio.NewEncoder(w).BadRequestWithError(ctx, err)
		}

		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		if err := a.manager.AddRole(ctx, domain, req.RoleName); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		resp := &response{
			Role: req.RoleName,
		}

		return httpio.NewEncoder(w).Ok(resp)
	})
}

// AddRolePermissions is the handler to assign permissions to a given role
//
// Permissions Required: AddRolePermissions
func (a *HandlerClient) AddRolePermissions() http.HandlerFunc {
	type request struct {
		Permissions []Permission `json:"permissions"`
	}

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.AddRolePermissions()")
		defer span.End()

		req := &request{}
		if err := a.NewDecoder(r).Decode(req); err != nil {
			return httpio.NewEncoder(w).BadRequestWithError(ctx, err)
		}

		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		role := Role(httpio.Param[string](r, paramRole))

		if err := a.manager.AddRolePermissions(ctx, req.Permissions, role, domain); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return nil
	})
}

// AddRoleUsers is the handler to assign a role to a list of users
//
// Permissions Required: AddRoleUsers
func (a *HandlerClient) AddRoleUsers() http.HandlerFunc {
	type request struct {
		Users []User
	}

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.AddRoleUsers()")
		defer span.End()

		req := &request{}
		if err := a.NewDecoder(r).Decode(req); err != nil {
			return httpio.NewEncoder(w).BadRequestWithError(ctx, err)
		}
		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		role := Role(httpio.Param[string](r, paramRole))

		if err := a.manager.AddRoleUsers(ctx, req.Users, role, domain); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return nil
	})
}

// DeleteRoleUsers is the handler to delete a list of users from a given role
//
// Permissions Required: DeleteRoleUsers
func (a *HandlerClient) DeleteRoleUsers() http.HandlerFunc {
	type request struct {
		Users []User
	}

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.DeleteRoleUsers()")
		defer span.End()

		req := &request{}
		if err := a.NewDecoder(r).Decode(req); err != nil {
			return httpio.NewEncoder(w).BadRequestWithError(ctx, err)
		}
		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		role := Role(httpio.Param[string](r, paramRole))

		if err := a.manager.DeleteRoleUsers(ctx, req.Users, role, domain); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return nil
	})
}

// DeleteRolePermissions is the handler to remove permissions from a role
//
// Permissions Required: DeleteRolePermissions
func (a *HandlerClient) DeleteRolePermissions() http.HandlerFunc {
	type request struct {
		Permissions []Permission `json:"permissions" validate:"min=1"`
	}

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.DeleteRolePermissions()")
		defer span.End()

		req := &request{}
		if err := a.NewDecoder(r).Decode(req); err != nil {
			return httpio.NewEncoder(w).BadRequestWithError(ctx, err)
		}
		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		role := Role(httpio.Param[string](r, paramRole))

		if err := a.manager.DeleteRolePermissions(ctx, req.Permissions, role, domain); err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return nil
	})
}

// Roles is the handler to get the list of roles in the system for a given domain
//
// Permissions Required: ListRoles
func (a *HandlerClient) Roles() http.HandlerFunc {
	type response struct {
		Roles []Role `json:"roles,omitempty"`
	}

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.Roles()")
		defer span.End()

		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		roles, err := a.manager.Roles(ctx, domain)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		res := &response{Roles: roles}

		return httpio.NewEncoder(w).Ok(res)
	})
}

// RoleUsers is the handler to the list of users for a given role
//
// Permissions Required: ListRoleUsers
func (a *HandlerClient) RoleUsers() http.HandlerFunc {
	type response []User

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.RoleUsers()")
		defer span.End()

		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		role := Role(httpio.Param[string](r, paramRole))

		roleUsers, err := a.manager.RoleUsers(ctx, role, domain)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		resp := response(roleUsers)

		return httpio.NewEncoder(w).Ok(resp)
	})
}

// RolePermissions is the handler to the list of permissions for a given role
//
// Permissions Required: ListRolePermissions
func (a *HandlerClient) RolePermissions() http.HandlerFunc {
	type response []Permission

	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.RolePermissions()")
		defer span.End()

		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		role := Role(httpio.Param[string](r, paramRole))

		rolePermissions, err := a.manager.RolePermissions(ctx, role, domain)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		resp := response(rolePermissions)

		return httpio.NewEncoder(w).Ok(resp)
	})
}

// DeleteRole is the handler to delete a role
//
// Permissions Required: DeleteRole
func (a *HandlerClient) DeleteRole() http.HandlerFunc {
	return a.handler(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := otel.Tracer(name).Start(r.Context(), "App.DeleteRole()")
		defer span.End()

		domain := Domain(httpio.Param[string](r, paramGuarantorID))
		role := Role(httpio.Param[string](r, paramRole))

		_, err := a.manager.DeleteRole(ctx, role, domain)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return nil
	})
}
