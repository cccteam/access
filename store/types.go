package store

// User represents a user in the system.
type User struct {
	ID   int64
	Name string
}

// Role represents a role in the system.
type Role struct {
	ID   int64
	Name string
}

// Permission represents a permission in the system.
type Permission struct {
	ID   int64
	Name string
}

// Resource represents a resource in the system.
type Resource struct {
	ID   int64
	Name string
}
