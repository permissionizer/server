package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"server/api"
	"server/types"
	"server/util"
	"strconv"
	"strings"
	"syscall"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/go-viper/mapstructure/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"go.uber.org/zap"
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
	viper.SetOptions(viper.ExperimentalBindStruct()) // allow binding envs to structs
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	viper.SetConfigName("permissionizer-server")
	viper.AddConfigPath("config/dev")
	viper.AddConfigPath("config")

	err := viper.ReadInConfig()
	if err != nil {
		sugar.Infow("Not found config in default location", "path", "config/permissionizer-server.yaml")
	}

	config := types.PermissionizerConfig{
		ExpectedAudience: "permissionizer-server (https://permissionizer.app)",
		RateLimit: types.RateLimitConfig{
			TokensPerMinute: 10.0,
			Overrides:       map[string]float64{},
		},
		Unsecure: types.UnsecureConfig{
			SkipTokenValidation: false,
		},
	}

	// prefix the config with "permissionizer"
	type Holder struct {
		Permissionizer *types.PermissionizerConfig `mapstructure:"permissionizer"`
	}
	holder := &Holder{Permissionizer: &config}

	decoderConfig := func(dc *mapstructure.DecoderConfig) {
		dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(pemToPrivateKeyHook(), stringToMapHook())
	}
	if err := viper.Unmarshal(&holder, decoderConfig); err != nil {
		sugar.Fatal("Failed to unmarshal config", err)
	}

	if config.ClientId == "" {
		sugar.Fatal("Missing 'permissionizer.client-id' configuration")
	}
	if config.PrivateKey == nil {
		sugar.Fatal("Missing 'permissionizer.private-key' configuration")
	}

	if config.Unsecure.SkipTokenValidation {
		sugar.Error("IDToken validation is disabled, this is only intended for local development and will not verify integrity of the tokens. If used in production, this will allow anyone to access any repository.")
	}

	return &config
}

func pemToPrivateKeyHook() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if f.Kind() == reflect.String && t == reflect.TypeOf(&rsa.PrivateKey{}) {
			privateKeyStr := data.(string)
			privateKeyStr = strings.ReplaceAll(privateKeyStr, "\\n", "\n")
			return jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyStr))
		}
		return data, nil
	}
}

func stringToMapHook() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if f.Kind() == reflect.String && t == reflect.TypeOf(map[string]float64{}) {
			result := make(map[string]float64)
			entries := strings.Split(data.(string), ",")
			for _, entry := range entries {
				parts := strings.SplitN(entry, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := parts[0]
				val, err := strconv.ParseFloat(parts[1], 64)
				if err != nil {
					return nil, err
				}
				result[key] = val
			}
			return result, nil
		}
		return data, nil
	}
}
