package main

import (
	"flag"
	"fmt"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"net/http"
	"os"
	"os/signal"
	"server/api"
	"server/types"
	"server/util"
	"strings"
	"syscall"
	"time"
)

var (
	version          = "dev"
	revision         = ""
	production       = flag.Bool("production", false, "Enable production mode")
	fakeToken        = flag.Bool("fake-token", false, "[Testing only] Generate token for testing purposes")
	tokenRepository  = flag.String("repository", "", "[Testing only] Issuing repository of the generated token")
	tokenRef         = flag.String("ref", "refs/head/main", "[Testing only] Ref of the generated token")
	tokenWorkflowRef = flag.String("workflow-ref", "", "[Testing only] Workflow ref of the generated token")
)

func main() {
	flag.Parse()
	exitIfCmd()

	var internalLogger *zap.Logger
	var err error
	if production != nil && *production {
		internalLogger, err = zap.NewProduction()
		gin.SetMode("release")
	} else {
		internalLogger, err = zap.NewDevelopment()
		gin.SetMode("debug")
	}
	if err != nil {
		panic(err)
	}
	logger := internalLogger.Sugar()

	config := initConfig(logger)

	// Create API instance with the client
	permissionizerApi := api.NewApi(config, logger)

	gin.EnableJsonDecoderDisallowUnknownFields()
	router := gin.New()
	router.UseH2C = true
	router.Use(ginzap.GinzapWithConfig(logger.Desugar(), &ginzap.Config{
		TimeFormat: time.RFC3339,
		UTC:        true,
	}))
	router.Use(ginzap.CustomRecoveryWithZap(logger.Desugar(), true, func(c *gin.Context, err any) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, &types.ProblemDetail{
			Type:   string(types.InternalError),
			Title:  "Internal Server Error",
			Status: http.StatusInternalServerError,
		})
	}))
	router.NoRoute(func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusNotFound, &types.ProblemDetail{
			Type:   string(types.InvalidRequest),
			Title:  "Not Found",
			Status: http.StatusNotFound,
		})
	})

	router.POST("/v1/token", permissionizerApi.IssueToken)
	router.POST("/v1/webhook", permissionizerApi.HandleWebhook)

	go func() {
		err := router.Run("0.0.0.0:8080")
		if err != nil {
			logger.Fatal(err)
		}
	}()
	logger.Infow("Server started", "port", 8080, "version", fmt.Sprintf("%s (%s)", version, revision))
	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")
}

func exitIfCmd() {
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

func initConfig(sugar *zap.SugaredLogger) *types.PermissionizerConfig {
	viper.AutomaticEnv()
	viper.AllowEmptyEnv(true)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	viper.SetConfigName("permissionizer-server")
	viper.AddConfigPath("config/dev")
	viper.AddConfigPath("config")

	viper.SetDefault("permissionizer.expected-audience", "permissionizer-server (https://permissionizer.app)")
	viper.SetDefault("permissionizer.unsecure-skip-token-checks", false)
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
		sugar.Error("IDToken validation is disabled, this is only intended for local development and will not verify integrity of the tokens. If used in production, this will allow anyone to access any repository.")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyStr))
	if err != nil {
		sugar.Fatal("Failed to parse private key found in 'permissionizer.private-key' config", err)
	}

	return &types.PermissionizerConfig{
		SkipTokenValidation: skipTokenValidation,
		ExpectedAudience:    expectedAudience,
		ClientId:            clientId,
		PrivateKey:          privateKey,
		WebhookSecret:       webhookSecret,
	}
}
