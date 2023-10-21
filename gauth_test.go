package gauth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

// JWTSuite holds a unit of test
type JWTSuite struct {
	log zerolog.Logger
	ctx context.Context
	suite.Suite
	g *[]GAuth
}

// GAuth holds the JWT input parameters
type GAuth struct {
	ID            string
	Subject       string
	Audience      string
	ExpirationDur *time.Duration
	Issuer        string
	SignedByte    []byte
	token         *jwt.Token
	str           string
}

// InitJWTSuite initializes a slice of JWTSuite
func InitJWTSuite() *[]GAuth {
	return &[]GAuth{
		{
			ID:            "",
			Subject:       "",
			Audience:      "",
			ExpirationDur: nil,
			Issuer:        "",
			SignedByte:    nil,
			token:         nil,
			str:           "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzYW1hIiwiZXhwIjoxNjk3ODQxMzUyNzk4MzI2MDAwLCJqdGkiOiJhZmRhMmFjNi1kZjNlLTRkODYtYmI1Yi05MmVkY2QzNGZhOTYiLCJpc3MiOiJhdXRoX3IiLCJzdWIiOiJ0ZXN0In0.3X5JH5W6N_n7NKct0uFc9uRuUoql73rpuJMG-ccjkrg",
		},
	}
}

func (s *JWTSuite) SetupTest() {
	s.log = zerolog.New(os.Stdout)
	s.log.Info().Msg("Starting tests...")
	s.ctx = context.Background()
	s.g = InitJWTSuite()

	s.log.Info().Msg("Tests startup complete...")
}

// TestIsIn tests that IsIn function works as expected
func (s *JWTSuite) TestJWTGeneration() {
	for i := 0; i < len(*s.g); i++ {
		step := *s.g
		jReq := UserJWTRequest{
			ID:            step[i].ID,
			Subject:       step[i].Subject,
			Audience:      step[i].Audience,
			ExpirationDur: step[i].ExpirationDur,
			Issuer:        step[i].Issuer,
			SignedByte:    step[i].SignedByte,
		}

		jwt, err := NewJWT(&jReq)
		// TODO: Go about testing by first, generating JWT tokens,
		// and then decoding them and comparing claims and header information
		s.Assert().NoError(err)

		s.Assert().Equalf(step[i].str, jwt.String(), "")
		s.Assert().Equalf(step[i].token, jwt.Token, "")
	}
}

func (s *JWTSuite) TearDownSuite() {
	s.log.Info().Msg("Commencing test cleanup")
	//err := cleanUpAfterCatTest()
	//s.Require().NoError(err)
	s.log.Info().Msg("All testing complete")
}

func TestUtilTest(t *testing.T) {
	suite.Run(t, new(JWTSuite))
}
