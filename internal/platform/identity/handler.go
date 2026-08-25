package identity

import (
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
)

type createUserRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type issueTokenRequest struct {
	TTL string `json:"ttl"`
}

type userView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
}

type userListView struct {
	Users []userView `json:"users"`
}

type tokenView struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Selector  string `json:"selector"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type tokenListView struct {
	Tokens []tokenView `json:"tokens"`
}

type issuedTokenView struct {
	tokenView
	Secret string `json:"secret"`
}

func userViewOf(u User) userView {
	return userView{
		ID:        u.ID,
		Name:      u.Name,
		Role:      u.Role,
		Disabled:  u.Disabled,
		CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func tokenViewOf(t Token) tokenView {
	view := tokenView{
		ID:        t.ID,
		UserID:    t.UserID,
		Selector:  t.Selector,
		CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !t.ExpiresAt.IsZero() {
		view.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return view
}

func (m *Module) handleCreateUser(w http.ResponseWriter, r *http.Request) error {
	req, err := httpx.Decode[createUserRequest](w, r)
	if err != nil {
		return err
	}

	u, err := m.service.createUser(r.Context(), CreateUserInput(req))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusCreated, userViewOf(u))
	return nil
}

func (m *Module) handleListUsers(w http.ResponseWriter, r *http.Request) error {
	users, err := m.service.listUsers(r.Context())
	if err != nil {
		return err
	}

	views := make([]userView, 0, len(users))
	for _, u := range users {
		views = append(views, userViewOf(u))
	}

	httpx.Write(w, http.StatusOK, userListView{Users: views})
	return nil
}

func (m *Module) handleGetUser(w http.ResponseWriter, r *http.Request) error {
	u, err := m.service.getUser(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusOK, userViewOf(u))
	return nil
}

func (m *Module) handleDeleteUser(w http.ResponseWriter, r *http.Request) error {
	if err := m.service.deleteUser(r.Context(), r.PathValue("id")); err != nil {
		return err
	}

	httpx.Write(w, http.StatusNoContent, nil)
	return nil
}

func (m *Module) handleIssueToken(w http.ResponseWriter, r *http.Request) error {
	ttl, err := m.requestedTTL(w, r)
	if err != nil {
		return err
	}

	t, secret, err := m.service.issueToken(r.Context(), r.PathValue("id"), ttl)
	if err != nil {
		return err
	}

	httpx.Write(w, http.StatusCreated, issuedTokenView{
		tokenView: tokenViewOf(t),
		Secret:    secret,
	})
	return nil
}

func (m *Module) requestedTTL(w http.ResponseWriter, r *http.Request) (time.Duration, error) {
	if r.ContentLength == 0 {
		return 0, nil
	}

	req, err := httpx.Decode[issueTokenRequest](w, r)
	if err != nil {
		return 0, err
	}
	if req.TTL == "" {
		return 0, nil
	}

	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		return 0, fault.Invalid("invalid_ttl", "ttl must be a duration such as 24h or 30m")
	}
	return ttl, nil
}

func (m *Module) handleListTokens(w http.ResponseWriter, r *http.Request) error {
	tokens, err := m.service.listTokens(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}

	views := make([]tokenView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, tokenViewOf(t))
	}

	httpx.Write(w, http.StatusOK, tokenListView{Tokens: views})
	return nil
}

func (m *Module) handleRevokeToken(w http.ResponseWriter, r *http.Request) error {
	if err := m.service.revokeToken(r.Context(), r.PathValue("id")); err != nil {
		return err
	}

	httpx.Write(w, http.StatusNoContent, nil)
	return nil
}
