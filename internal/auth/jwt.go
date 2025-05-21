package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenClaims represents the JWT claims
type TokenClaims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateJWTToken creates a new JWT token for a user
func GenerateJWTToken(userID uint, secret string, expiresIn time.Duration) (string, error) {
	claims := &TokenClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "vec-server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// VerifyJWTToken validates a JWT token and returns its claims
func VerifyJWTToken(tokenString, secret string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
