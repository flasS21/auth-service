package session

import (
	"net/http"
	"time"
)

const (
	CookieName = "__Host-session"
)

// CookieOptions defines how session cookies are issued.
type CookieOptions struct {
	Secure   bool
	SameSite http.SameSite
	Domain   string // should usually be empty for __Host- cookies
}

// SetCookie issues the session cookie to the client.
func SetCookie(w http.ResponseWriter, sessionID string, expiresAt time.Time, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sessionID,
		Path:     "/", // required for __Host-
		Domain:   opts.Domain,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: opts.SameSite,
	})
}

// ClearCookie removes the session cookie from the client.
func ClearCookie(w http.ResponseWriter, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Domain:   opts.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: opts.SameSite,
	})
}
