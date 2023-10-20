package main

import (
	"time"

	"github.com/golang-jwt/jwt"
)

// Be able to generate JWT tokens and validate,
//and set up authentication and authorization stuff

// Authenticator describes the method set that every authentication method
// defined in this package must adhere to
type Authenticator interface {
	IsValidJWT() bool
	WithCustom(admin bool) *JWT
}

// UserJWTRequest serves as the request struct for JWTs
type UserJWTRequest struct {
	ID            string //uuid generated on login
	Subject       string
	Audience      string
	ExpirationDur *time.Duration
	Issuer        string
}

// JWT is the structure for JWT within this package
type JWT struct {
	Token *jwt.Token
	//custom *jwt.MapClaims
}

func NewJWT(u *UserJWTRequest) *JWT {
	claims := jwt.StandardClaims{}
	claims.Subject = u.Subject
	claims.Audience = u.Audience
	claims.ExpiresAt = time.Now().Add(*u.ExpirationDur).UnixNano()
	claims.Id = u.ID
	claims.Issuer = u.Issuer

	return &JWT{
		Token: jwt.NewWithClaims(jwt.SigningMethodHS256, claims),
	}
}

// TODO: Implement custom JWT claims later
//func (j *JWT) WithCustom(admin bool) *JWT {
//	j.custom = &jwt.MapClaims{
//		"admin": admin,
//	}
//	return j
//}

// IsValid validates time based claims "exp, iat, nbf". There is no accounting for clock skew.
// As well, if any of the above claims are not in the token,
// it will still be considered a valid claim.
func (j *JWT) IsValid() bool {
	err := j.Token.Claims.Valid()
	if err != nil {
		return false
	}
	return true
}
