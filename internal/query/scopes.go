package query

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/store"
)

// errForbiddenApp is returned for a decision on an application the caller's role does not reach.
var errForbiddenApp = errors.New("your role does not allow this on that application")

// roleScope is what a caller may do where: the tenant role is the floor, and an access binding raises it for
// one application (docs/16 D48).
type roleScope struct {
	tenant auth.Role
	apps   map[uuid.UUID]auth.Role
}

func higher(a, b auth.Role) auth.Role {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// on is the caller's role on an application.
func (s roleScope) on(app uuid.UUID) auth.Role { return higher(s.tenant, s.apps[app]) }

// anywhere is the highest role the caller holds anywhere. An endpoint uses it as its door; the decision on a
// particular application is checked where the application is known.
func (s roleScope) anywhere() auth.Role {
	best := s.tenant
	for _, r := range s.apps {
		best = higher(best, r)
	}
	return best
}

func (s roleScope) allows(app uuid.UUID, min auth.Role) bool { return s.on(app).Rank() >= min.Rank() }

// scopeOf loads the bindings of the caller. A store without bindings (the in-memory one) gives the tenant role only.
func (a *API) scopeOf(ctx context.Context, tenantID uuid.UUID, user *auth.ContextUser) roleScope {
	sc := roleScope{tenant: user.Role, apps: map[uuid.UUID]auth.Role{}}
	bs, ok := a.store.(store.AccessBindings)
	if !ok {
		return sc
	}
	list, err := bs.BindingsFor(ctx, tenantID, []string{user.Email, user.Subject})
	if err != nil {
		return sc // fail closed: the tenant role alone
	}
	for _, b := range list {
		if r, ok := auth.ParseRole(b.Role); ok {
			sc.apps[b.ApplicationID] = higher(sc.apps[b.ApplicationID], r)
		}
	}
	return sc
}

// requireAny authenticates, and lets the caller through when some role they hold, on the tenant or on any one
// application, reaches min. The caller then checks the application with scope.allows.
func (a *API) requireAny(w http.ResponseWriter, r *http.Request, min auth.Role) (uuid.UUID, *auth.ContextUser, roleScope, bool) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return uuid.Nil, nil, roleScope{}, false
	}
	sc := a.scopeOf(r.Context(), tenantID, user)
	if sc.anywhere().Rank() < min.Rank() {
		problem(w, http.StatusForbidden, "forbidden", "Your role does not allow this: it needs "+string(min))
		return uuid.Nil, nil, roleScope{}, false
	}
	return tenantID, user, sc, true
}

// allowFor is the check triageOne makes once it knows the finding's application.
func (s roleScope) allowFor(min auth.Role) func(uuid.UUID) bool {
	return func(app uuid.UUID) bool { return s.allows(app, min) }
}
