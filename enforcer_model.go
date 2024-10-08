package access

// rbacModel is the perm model for the casbin enforcer
func rbacModel() string {
	return `
		[request_definition]
		r = sub, dom, obj, act
		
		[policy_definition]
		p = sub, dom, obj, act, eft
		
		[role_definition]
		g = _, _, _
		
		[policy_effect]
		e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
		
		[matchers]
		m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act && r.sub != "noop"
	`
}
