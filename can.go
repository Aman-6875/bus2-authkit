package authkit

// PermissionResolver answers "what abilities does this role grant?". authkit
// depends on this interface rather than a concrete store so the lookup can
// start as a static snapshot and later become a live, event-kept-fresh
// cache without changing Can's signature or any caller.
type PermissionResolver interface {
	Permissions(role string) []string
}

// StaticPermissions is a PermissionResolver backed by a fixed, in-memory
// role-to-permissions map. It never changes after construction — useful for
// tests and for a first working version before the live cache exists.
type StaticPermissions map[string][]string

// Permissions implements PermissionResolver.
func (p StaticPermissions) Permissions(role string) []string {
	return p[role]
}

// Can reports whether any role in claims grants ability, per resolver.
func Can(claims Claims, ability string, resolver PermissionResolver) bool {
	for _, role := range claims.Roles {
		for _, granted := range resolver.Permissions(role) {
			if granted == ability {
				return true
			}
		}
	}
	return false
}
