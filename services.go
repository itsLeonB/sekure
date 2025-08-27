package sekure

// keep for now

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/itsLeonB/sekure/internal"
	"github.com/itsLeonB/sekure/lib"
	"github.com/itsLeonB/ungerr"
	"github.com/rotisserie/eris"
)

// JWTClaims represents the claims structure for JWT tokens.
// It extends jwt.RegisteredClaims with custom data payload for application-specific information.
type JWTClaims struct {
	jwt.RegisteredClaims
	Data map[string]any `json:"data"` // Custom application data
}

// JWTService provides an interface for JWT token operations.
// It abstracts token creation and verification for different signing algorithms.
type JWTService interface {
	// CreateToken generates a new JWT token with the provided data payload.
	CreateToken(data map[string]any) (string, error)
	// VerifyToken validates a JWT token string and returns the claims.
	VerifyToken(tokenstr string) (JWTClaims, error)
}

type jwtServiceHS256 struct {
	issuer        string
	secretKey     string
	tokenDuration time.Duration
}

// NewJwtService creates a new JWT service implementation using HMAC SHA256 signing.
// It uses the provided Auth configuration for token settings and validation.
func NewJwtService(issuer, secretKey string, tokenDuration time.Duration) JWTService {
	return &jwtServiceHS256{
		issuer,
		secretKey,
		tokenDuration,
	}
}

// CreateToken generates a new JWT token with the provided data payload.
// The token includes standard claims (issuer, expiration, issued at) and custom data.
// Returns the signed token string or an error if signing fails.
func (j *jwtServiceHS256) CreateToken(data map[string]any) (string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    j.issuer,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.tokenDuration)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Data: data,
		},
	)

	signed, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		return "", eris.Wrap(err, "error signing token")
	}

	return signed, nil
}

// VerifyToken validates a JWT token string and extracts the claims.
// It verifies the signature, issuer, expiration, and signing method.
// Returns the parsed claims or an appropriate error (including UnauthorizedError for expired tokens).
func (j *jwtServiceHS256) VerifyToken(tokenstr string) (JWTClaims, error) {
	var claims JWTClaims

	_, err := jwt.ParseWithClaims(
		tokenstr,
		&claims,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(j.secretKey), nil
		},
		jwt.WithIssuer(j.issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return claims, ungerr.UnauthorizedError(lib.MsgAuthExpiredToken)
		}

		return claims, eris.Wrap(err, "error parsing token")
	}

	return claims, nil
}

// HashService provides an interface for password hashing and verification.
// It abstracts different hashing algorithms for secure password storage.
type HashService interface {
	// Hash generates a secure hash of the input value.
	Hash(val string) (string, error)
	// CheckHash verifies if a value matches the provided hash.
	CheckHash(hash, val string) (bool, error)
}

// NewHashService creates a new hash service implementation using bcrypt.
// The cost parameter determines the computational cost of hashing (defaults to 10 if negative).
// Higher cost values provide better security but slower performance.
func NewHashService(cost int) HashService {
	if cost < 0 {
		cost = 10 // TODO: make this configurable
	}
	return &internal.HashServiceBcrypt{Cost: cost}
}
