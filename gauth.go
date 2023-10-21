package gauth

import (
	"reflect"
	"time"

	"github.com/golang-jwt/jwt"
)

// Be able to generate JWT tokens and validate,
//and set up authentication and authorization stuff

type JWTStrand string

// Authenticator describes the method set that every authentication method
// defined in this package must adhere to
type Authenticator interface {
	IsValidJWT() bool
	WithCustom(admin bool) *JWT
}

// UserJWTRequest serves as the request struct for JWTs
type UserJWTRequest struct {
	// ID is Login request uuid generated
	ID string
	// Subject is the User id as registered in the datastore
	Subject       string
	Audience      string
	ExpirationDur *time.Duration
	Issuer        string
	SignedByte    []byte
}

// JWT is the structure for JWT within this package
type JWT struct {
	Token *jwt.Token
	//custom *jwt.MapClaims
	str JWTStrand
}

// NewJWT creates a new JWT struct with the parameters from the request struct
func NewJWT(u *UserJWTRequest) (*JWT, error) {
	claims := jwt.StandardClaims{}
	claims.Subject = u.Subject
	claims.Audience = u.Audience
	claims.ExpiresAt = time.Now().Add(*u.ExpirationDur).UnixNano()
	claims.Id = u.ID // login ID
	claims.Issuer = u.Issuer

	j := &JWT{
		Token: jwt.NewWithClaims(jwt.SigningMethodHS256, claims),
	}

	str, err := j.Token.SignedString(u.SignedByte)
	j.str = JWTStrand(str)
	if err != nil {
		return nil, err
	}

	return j, nil
}

// String returns the generated JWTStrand
func (j *JWT) String() JWTStrand {
	return j.str
}

//// Println returns the whole Token structure
//func (j *JWT) Println() string {
//	return j.Token.Claims(jwt.StandardClaims)
//}

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

func (j *JWTStrand) Decode(secret []byte) (*JWT, error) {
	ref := reflect.ValueOf(*j)
	if ref.Kind() != reflect.String {
		return nil, nil
	}

	token, err := jwt.ParseWithClaims(ref.String(), &jwt.StandardClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		})
	if err != nil {
		return nil, err
	}

	return &JWT{
		Token: token,
		str:   *j,
	}, nil
}
