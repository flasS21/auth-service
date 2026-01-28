package credentials

import (
	"context"
	"database/sql"
	"errors"

	"auth-service/internal/db"

	"github.com/google/uuid"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAlreadyRegistered  = errors.New("credentials already exist")
)

type Service struct {
	db *db.DB
}

func NewService(db *db.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Register(
	ctx context.Context,
	email string,
	password string,
) (string, error) {

	var userID uuid.UUID

	// 1. Find or create user by email
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM users
		WHERE LOWER(email) = LOWER($1)
	`, email).Scan(&userID)

	if err == sql.ErrNoRows {
		// create new user
		err = s.db.QueryRowContext(ctx, `
			INSERT INTO users (email, email_verified)
			VALUES ($1, false)
			RETURNING id
		`, email).Scan(&userID)
	}

	if err != nil {
		return "", err
	}

	// 2. Check if credentials already exist
	var exists bool
	err = s.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM credentials WHERE user_id = $1
		)
	`, userID).Scan(&exists)

	if err != nil {
		return "", err
	}

	if exists {
		return "", ErrAlreadyRegistered
	}

	// 3. Hash password
	hash, version, err := HashPassword(password)
	if err != nil {
		return "", err
	}

	// 4. Insert credentials
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO credentials (user_id, password_hash, hash_version)
		VALUES ($1, $2, $3)
	`, userID, hash, version)

	if err != nil {
		return "", err
	}

	return userID.String(), nil
}

func (s *Service) Authenticate(
	ctx context.Context,
	email string,
	password string,
) (string, error) {

	var (
		userID       uuid.UUID
		passwordHash string
	)

	// 1. Find user + credentials
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, c.password_hash
		FROM users u
		JOIN credentials c ON c.user_id = u.id
		WHERE LOWER(u.email) = LOWER($1)
	`, email).Scan(&userID, &passwordHash)

	if err != nil {
		// hide whether user exists or not
		return "", ErrInvalidCredentials
	}

	// 2. Verify password
	if err := VerifyPassword(passwordHash, password); err != nil {
		return "", ErrInvalidCredentials
	}

	return userID.String(), nil
}
