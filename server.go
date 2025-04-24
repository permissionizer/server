package main

import (
	"context"
	"crypto/rsa"
	"flag"
	"fmt"
	"os"
	"server/permissionizer"
	"server/util"
	"strings"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v71/github"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type config struct {
	skipTokenValidation bool
	expectedAudience    string
	clientId            string
	privateKey          *rsa.PrivateKey
	webhookSecret       string
}

var (
	fakeToken        = flag.Bool("fake-token", false, "[Testing only] Generate token for testing purposes")
	tokenRepository  = flag.String("repository", "", "[Testing only] Issuing repository of the generated token")
	tokenRef         = flag.String("ref", "refs/head/main", "[Testing only] Ref of the generated token")
	tokenWorkflowRef = flag.String("workflow-ref", "", "[Testing only] Workflow ref of the generated token")
)

func main() {
	exitIfCmd()

	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	config := initConfig(sugar)

	authenticatedClient := oauth2.NewClient(context.Background(), &jwtTokenSource{
		clientId:   config.clientId,
		privateKey: config.privateKey,
	})

	githubClient := github.NewClient(authenticatedClient)

	// Create API instance with the client
	permissionizerApi := permissionizer.NewApi(githubClient, config.expectedAudience, config.webhookSecret, config.skipTokenValidation)

	gin.SetMode("release")
	router := gin.New()
	router.Use(ginzap.Ginzap(logger, time.RFC3339, true))

	router.POST("/v1/token", permissionizerApi.IssueToken)
	router.POST("/v1/webhook", permissionizerApi.HandleWebhook)

	router.Run("localhost:8080")
}

func exitIfCmd() {
	flag.Parse()
	if fakeToken != nil && *fakeToken {
		if *tokenRepository == "" {
			println("'--repository' must be set")
			os.Exit(1)
		}
		if *tokenWorkflowRef == "" {
			tokenWorkflowRef = util.Ptr(*tokenRepository + "/.github/workflows/fake-token.yaml@" + *tokenRef)
		}
		fmt.Println(util.GenerateUnsignedIDToken("permissionizer-server (https://permissionizer.app)", *tokenRepository, *tokenRef, *tokenWorkflowRef))
		os.Exit(0)
	}
}

func initConfig(sugar *zap.SugaredLogger) *config {
	viper.AutomaticEnv()
	viper.AllowEmptyEnv(true)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	viper.SetConfigName("permissionizer-server")
	viper.AddConfigPath("config/dev")
	viper.AddConfigPath("config")

	viper.SetDefault("expected-audience", "permissionizer-server (https://permissionizer.app)")
	viper.SetDefault("unsecure-skip-token-checks", false)
	err := viper.ReadInConfig()
	if err != nil {
		sugar.Infow("Not found config in default location", "path", "config/permissionizer-server.yaml")
	}

	skipTokenValidation := viper.GetBool("permissionizer.unsecure-skip-token-validation")
	expectedAudience := viper.GetString("permissionizer.expected-audience")
	clientId := viper.GetString("permissionizer.client-id")
	privateKeyStr := viper.GetString("permissionizer.private-key")
	webhookSecret := viper.GetString("permissionizer.webhook-secret")
	if clientId == "" {
		sugar.Fatal("Missing 'permissionizer.client-id' configuration")
	}
	if privateKeyStr == "" {
		sugar.Fatal("Missing 'permissionizer.private-key' configuration")
	}
	if skipTokenValidation {
		sugar.Error("IDToken validation are disabled, this is only intended for local development and will not verify integrity of the tokens. If used in production, this will allow anyone to access any repository.")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyStr))
	if err != nil {
		sugar.Fatal("Failed to parse private key found in 'permissionizer.private-key' config", err)
	}

	return &config{
		skipTokenValidation: skipTokenValidation,
		expectedAudience:    expectedAudience,
		clientId:            clientId,
		privateKey:          privateKey,
		webhookSecret:       webhookSecret,
	}
}

type jwtTokenSource struct {
	clientId   string
	privateKey *rsa.PrivateKey
}

func (tokenSource *jwtTokenSource) Token() (*oauth2.Token, error) {
	// To protect against clock drift, set the issuance time 60 seconds in the past.
	now := time.Now().Add(-60 * time.Second)
	expiresAt := now.Add(10 * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Issuer:    tokenSource.clientId,
	})

	tokenString, err := token.SignedString(tokenSource.privateKey)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		Expiry:      expiresAt,
	}, nil
}
