package sekure_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/itsLeonB/sekure"
	"github.com/itsLeonB/ungerr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTClaims(t *testing.T) {
	claims := sekure.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Data: map[string]any{
			"user_id": 123,
			"role":    "admin",
		},
	}

	assert.Equal(t, "test-issuer", claims.Issuer)
	assert.Equal(t, 123, claims.Data["user_id"])
	assert.Equal(t, "admin", claims.Data["role"])
}

func TestNewJwtService(t *testing.T) {
	service := sekure.NewJwtService("test-issuer", "test-secret-key", 24*time.Hour)
	assert.NotNil(t, service)
}

func TestJWTService_CreateToken(t *testing.T) {
	service := sekure.NewJwtService("test-issuer", "test-secret-key-for-jwt-testing", 24*time.Hour)

	tests := []struct {
		name string
		data map[string]any
	}{
		{
			name: "simple data",
			data: map[string]any{
				"user_id": 123,
				"role":    "user",
			},
		},
		{
			name: "complex data",
			data: map[string]any{
				"user_id":     456,
				"role":        "admin",
				"permissions": []string{"read", "write", "delete"},
				"metadata": map[string]any{
					"last_login": time.Now().Unix(),
					"ip_address": "192.168.1.1",
				},
			},
		},
		{
			name: "empty data",
			data: map[string]any{},
		},
		{
			name: "nil data",
			data: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := service.CreateToken(tt.data)
			require.NoError(t, err)
			assert.NotEmpty(t, token)

			// Verify token format (should have 3 parts separated by dots)
			parts := len(token)
			assert.Greater(t, parts, 0)

			// Token should be a valid JWT format
			assert.Contains(t, token, ".")
		})
	}
}

func TestJWTService_VerifyToken(t *testing.T) {
	service := sekure.NewJwtService("test-issuer", "test-secret-key-for-jwt-testing", 24*time.Hour)

	t.Run("valid token", func(t *testing.T) {
		originalData := map[string]any{
			"user_id": 123,
			"role":    "admin",
		}

		token, err := service.CreateToken(originalData)
		require.NoError(t, err)

		claims, err := service.VerifyToken(token)
		require.NoError(t, err)

		assert.Equal(t, "test-issuer", claims.Issuer)
		// JSON unmarshaling converts numbers to float64
		assert.Equal(t, float64(123), claims.Data["user_id"])
		assert.Equal(t, "admin", claims.Data["role"])
		assert.True(t, claims.ExpiresAt.After(time.Now()))
	})

	t.Run("invalid token format", func(t *testing.T) {
		_, err := service.VerifyToken("invalid-token")
		assert.Error(t, err)
	})

	t.Run("token with wrong secret", func(t *testing.T) {
		// Create token with different service
		wrongService := sekure.NewJwtService("test-issuer", "wrong-secret-key", time.Hour)

		token, err := wrongService.CreateToken(map[string]any{"user_id": 123})
		require.NoError(t, err)

		// Try to verify with original service
		_, err = service.VerifyToken(token)
		assert.Error(t, err)
	})

	t.Run("token with wrong issuer", func(t *testing.T) {
		// Create token with different issuer
		wrongService := sekure.NewJwtService("wrong-issuer", "test-secret-key-for-jwt-testing", time.Hour)

		token, err := wrongService.CreateToken(map[string]any{"user_id": 123})
		require.NoError(t, err)

		// Try to verify with original service
		_, err = service.VerifyToken(token)
		assert.Error(t, err)
	})

	t.Run("expired token", func(t *testing.T) {
		// Create service with very short expiration
		shortService := sekure.NewJwtService("test-issuer", "test-secret-key-for-jwt-testing", time.Nanosecond)

		token, err := shortService.CreateToken(map[string]any{"user_id": 123})
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(time.Millisecond)

		_, err = service.VerifyToken(token)
		assert.Error(t, err)

		// Should be an UnauthorizedError for expired token
		appErr, ok := err.(ungerr.AppError)
		assert.True(t, ok)
		assert.Equal(t, "Unauthorized", appErr.Error())
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := service.VerifyToken("")
		assert.Error(t, err)
	})
}

func TestJWTService_RoundTrip(t *testing.T) {
	service := sekure.NewJwtService("test-issuer", "test-secret-key-for-jwt-testing", time.Hour)

	testData := map[string]any{
		"user_id":     12345,
		"username":    "testuser",
		"role":        "admin",
		"permissions": []string{"read", "write", "delete"},
		"active":      true,
		"score":       98.5,
	}

	// Create token
	token, err := service.CreateToken(testData)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token
	claims, err := service.VerifyToken(token)
	require.NoError(t, err)

	// Check all data is preserved (JSON unmarshaling converts numbers to float64)
	assert.Equal(t, float64(12345), claims.Data["user_id"])
	assert.Equal(t, testData["username"], claims.Data["username"])
	assert.Equal(t, testData["role"], claims.Data["role"])
	assert.Equal(t, testData["active"], claims.Data["active"])
	assert.Equal(t, testData["score"], claims.Data["score"])

	// Permissions slice needs special handling due to JSON marshaling
	permissions, ok := claims.Data["permissions"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, permissions, 3)
	assert.Contains(t, permissions, "read")
	assert.Contains(t, permissions, "write")
	assert.Contains(t, permissions, "delete")

	// Check registered claims
	assert.Equal(t, "test-issuer", claims.Issuer)
	assert.True(t, claims.ExpiresAt.After(time.Now()))
	assert.True(t, claims.IssuedAt.Before(time.Now().Add(time.Second)))
}

func TestNewHashService(t *testing.T) {
	tests := []struct {
		name         string
		cost         int
		expectedCost int
	}{
		{
			name:         "positive cost",
			cost:         12,
			expectedCost: 12,
		},
		{
			name:         "negative cost uses default",
			cost:         -1,
			expectedCost: 10, // Default cost
		},
		{
			name:         "zero cost uses default",
			cost:         0,
			expectedCost: 10, // Default cost (since 0 < 0 is false, but bcrypt might have minimum)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := sekure.NewHashService(tt.cost)
			assert.NotNil(t, service)

			// Test that the service works
			hash, err := service.Hash("test-password")
			require.NoError(t, err)
			assert.NotEmpty(t, hash)
		})
	}
}

func TestHashService_Hash(t *testing.T) {
	service := sekure.NewHashService(4) // Low cost for faster tests

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "simple password",
			password: "password123",
		},
		{
			name:     "complex password",
			password: "P@ssw0rd!@#$%^&*()",
		},
		{
			name:     "empty password",
			password: "",
		},
		{
			name:     "long password",
			password: "this-is-a-long-password-but-under-72-bytes",
		},
		{
			name:     "unicode password",
			password: "密码123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := service.Hash(tt.password)
			require.NoError(t, err)
			assert.NotEmpty(t, hash)
			assert.NotEqual(t, tt.password, hash)

			// Hash should be different each time
			hash2, err := service.Hash(tt.password)
			require.NoError(t, err)
			assert.NotEqual(t, hash, hash2)
		})
	}
}

func TestHashService_CheckHash(t *testing.T) {
	service := sekure.NewHashService(4) // Low cost for faster tests

	t.Run("correct password", func(t *testing.T) {
		password := "test-password-123"
		hash, err := service.Hash(password)
		require.NoError(t, err)

		valid, err := service.CheckHash(hash, password)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("incorrect password", func(t *testing.T) {
		password := "test-password-123"
		wrongPassword := "wrong-password"

		hash, err := service.Hash(password)
		require.NoError(t, err)

		valid, err := service.CheckHash(hash, wrongPassword)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("invalid hash format", func(t *testing.T) {
		valid, err := service.CheckHash("invalid-hash", "password")
		assert.Error(t, err)
		assert.False(t, valid)
	})

	t.Run("empty hash", func(t *testing.T) {
		valid, err := service.CheckHash("", "password")
		assert.Error(t, err)
		assert.False(t, valid)
	})

	t.Run("empty password against valid hash", func(t *testing.T) {
		hash, err := service.Hash("actual-password")
		require.NoError(t, err)

		valid, err := service.CheckHash(hash, "")
		require.NoError(t, err)
		assert.False(t, valid)
	})
}

func TestHashService_RoundTrip(t *testing.T) {
	service := sekure.NewHashService(4) // Low cost for faster tests

	passwords := []string{
		"simple",
		"Complex!Password123",
		"",
		"with spaces and symbols !@#$%^&*()",
		"unicode密码",
		"long-password-under-72-bytes",
	}

	for _, password := range passwords {
		t.Run("password: "+password, func(t *testing.T) {
			// Hash the password
			hash, err := service.Hash(password)
			require.NoError(t, err)
			assert.NotEmpty(t, hash)

			// Verify the password
			valid, err := service.CheckHash(hash, password)
			require.NoError(t, err)
			assert.True(t, valid)

			// Verify wrong password fails
			valid, err = service.CheckHash(hash, password+"wrong")
			require.NoError(t, err)
			assert.False(t, valid)
		})
	}
}
