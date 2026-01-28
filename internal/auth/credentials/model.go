package credentials

import "time"

type Credential struct {
	ID           string
	UserID       string
	PasswordHash string
	HashVersion  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
