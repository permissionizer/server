package main

import (
	"os"
	"path"
	"server/types"
	"strings"
	"testing"

	"github.com/onsi/gomega"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const samplePrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDmavZsWCBuzErLpZWuOZs1GYZ8Oo+IZukckGENvipQt7j8OPcV
BkZOlxTf7TFlQDqCNrZLYitY3/BP2vsAo9NzXgYueTlgynLNrpWiEnvLDAUiv8Uk
VnkYIBgJQ7VZnwcq73CgJKtDMwBbiVPjagJynSYTgsu4LXeiClFiG5l1nwIDAQAB
AoGAQbYLZMaVKUP1qLImR7OCAdivs8n3mQzQOicqpoKvCqn6hWOxgztw3YTUnS/F
wHxaszvrLQBoIEZtADkREBOof1mVplG17mZKDsQjn9s3uPgeYpwDbGhQtOX4qKVE
lX+I+AK2vkNWoF5Xn1Awtd4MLuxmE4388xziecozNCUXF6ECQQD8aoH+77fNQzeP
xIBu2ZsFXNCJLUTkXWy2a9Ly/VKFJs7dwCvRCnK8C/FRmDroSTpz5s2haeRa1gQ6
P5DW838XAkEA6bB+p95T3y7ODpEVYeSWwcUFOs/AYldRW7wss25hnD1Xm7ELL6Wx
zBGtQRL9lUhJYlnDkI/cumuc7UkmNsUSuQJAUNDtFCm+SIsH5BD/Kf6kAqCH6BPF
ZfR/lRyKqt/uptEZFKitnr1gpNKSDhTWb37apzcziUW1Jlw1eEzX2+qUOwJBAJrY
ynQti+HdP8jDNinxsDuhc3+u3cnMFir1G6GhyKggtYaC3+iooJGaPPVbwhBDH+09
kaqeySH14LwStnGgUHECQEjNbxBt8o8949Kdjugx8ystrEF5Wp5Niqr7teeHaxUI
ZNjzXf+1ZADCWPuk+6AaGvM+489XxwbtoBoacaPemX8=
-----END RSA PRIVATE KEY-----
`

func TestInitConfigFailsWithoutClientIdOrPrivateKey(t *testing.T) {
	gomega.RegisterTestingT(t)
	reset()

	logger, _ := zap.NewDevelopment()

	gomega.PanicWith(func() {
		initConfig(logger.Sugar())
	})
	t.Setenv("PERMISSIONIZER_CLIENT_ID", "test-client-id")

	gomega.PanicWith(func() {
		initConfig(logger.Sugar())
	})

	t.Setenv("PERMISSIONIZER_PRIVATE_KEY", strings.ReplaceAll(samplePrivateKey, "\n", "\\n"))

	config := initConfig(logger.Sugar())

	gomega.Expect(config.ClientId).To(gomega.Equal("test-client-id"))
	gomega.Expect(config.WebhookSecret).To(gomega.Equal(""))
	gomega.Expect(config.ExpectedAudience).To(gomega.Equal("permissionizer-server (https://permissionizer.app)"))
	gomega.Expect(config.PrivateKey).NotTo(gomega.BeNil())
	gomega.Expect(config.RateLimit).To(gomega.Equal(types.RateLimitConfig{
		TokensPerMinute: 10.0,
		Overrides:       map[string]float64{},
	}))
	gomega.Expect(config.Unsecure.SkipTokenValidation).To(gomega.BeFalse())
}

func TestInitConfigLoadsWithDefaults(t *testing.T) {
	gomega.RegisterTestingT(t)
	reset()

	t.Setenv("PERMISSIONIZER_CLIENT_ID", "test-client-id")
	t.Setenv("PERMISSIONIZER_PRIVATE_KEY", strings.ReplaceAll(samplePrivateKey, "\n", "\\n"))

	logger, _ := zap.NewDevelopment()
	config := initConfig(logger.Sugar())

	gomega.Expect(config.ClientId).To(gomega.Equal("test-client-id"))
	gomega.Expect(config.WebhookSecret).To(gomega.Equal(""))
	gomega.Expect(config.ExpectedAudience).To(gomega.Equal("permissionizer-server (https://permissionizer.app)"))
	gomega.Expect(config.PrivateKey).NotTo(gomega.BeNil())
	gomega.Expect(config.RateLimit).To(gomega.Equal(types.RateLimitConfig{
		TokensPerMinute: 10.0,
		Overrides:       map[string]float64{},
	}))
	gomega.Expect(config.Unsecure.SkipTokenValidation).To(gomega.BeFalse())
}

func TestLoadConfigFromFile(t *testing.T) {
	gomega.RegisterTestingT(t)
	reset()

	configText := `
permissionizer:
  expected-audience: permissionizer-server (https://permissionizer-test.app)
  client-id: test-client-id
  private-key: |` + strings.ReplaceAll(samplePrivateKey, "\n", "\n"+strings.Repeat(" ", 4)) + `
  webhook-secret: test-secret
  rate-limit:
    tokens-per-minute: 20
    overrides:
      permissionizer: 60
      permissionizer/request-token: 100
  unsecure:
    skip-token-validation: true`
	tmpFile := useTestConfig(configText)
	defer os.Remove(tmpFile.Name())

	logger, _ := zap.NewDevelopment()

	config := initConfig(logger.Sugar())
	gomega.Expect(config).ToNot(gomega.BeNil())

	gomega.Expect(config.ClientId).To(gomega.Equal("test-client-id"))
	gomega.Expect(config.WebhookSecret).To(gomega.Equal("test-secret"))
	gomega.Expect(config.ExpectedAudience).To(gomega.Equal("permissionizer-server (https://permissionizer-test.app)"))
	gomega.Expect(config.PrivateKey).NotTo(gomega.BeNil())
	gomega.Expect(config.RateLimit).To(gomega.Equal(types.RateLimitConfig{
		TokensPerMinute: 20.0,
		Overrides: map[string]float64{
			"permissionizer":               60.0,
			"permissionizer/request-token": 100.0,
		},
	}))
	gomega.Expect(config.Unsecure.SkipTokenValidation).To(gomega.BeTrue())
}

func TestLoadConfigFromEnvs(t *testing.T) {
	gomega.RegisterTestingT(t)
	reset()

	t.Setenv("PERMISSIONIZER_CLIENT_ID", "test-client-id")
	t.Setenv("PERMISSIONIZER_PRIVATE_KEY", samplePrivateKey)
	t.Setenv("PERMISSIONIZER_EXPECTED_AUDIENCE", "permissionizer-server (https://permissionizer-test.app)")
	t.Setenv("PERMISSIONIZER_WEBHOOK_SECRET", "test-secret")
	t.Setenv("PERMISSIONIZER_RATE_LIMIT_TOKENS_PER_MINUTE", "20")
	t.Setenv("PERMISSIONIZER_RATE_LIMIT_OVERRIDES", "permissionizer=60,permissionizer/request-token=100")
	t.Setenv("PERMISSIONIZER_UNSECURE_SKIP_TOKEN_VALIDATION", "true")

	logger, _ := zap.NewDevelopment()

	config := initConfig(logger.Sugar())
	gomega.Expect(config).ToNot(gomega.BeNil())

	gomega.Expect(config.ClientId).To(gomega.Equal("test-client-id"))
	gomega.Expect(config.WebhookSecret).To(gomega.Equal("test-secret"))
	gomega.Expect(config.ExpectedAudience).To(gomega.Equal("permissionizer-server (https://permissionizer-test.app)"))
	gomega.Expect(config.PrivateKey).NotTo(gomega.BeNil())
	gomega.Expect(config.RateLimit).To(gomega.Equal(types.RateLimitConfig{
		TokensPerMinute: 20.0,
		Overrides: map[string]float64{
			"permissionizer":               60.0,
			"permissionizer/request-token": 100.0,
		},
	}))
	gomega.Expect(config.Unsecure.SkipTokenValidation).To(gomega.BeTrue())
}

func TestLoadConfigFromMinimalFile(t *testing.T) {
	gomega.RegisterTestingT(t)
	reset()

	configText := `
permissionizer:
  client-id: test-client-id
  private-key: |` + strings.ReplaceAll(samplePrivateKey, "\n", "\n"+strings.Repeat(" ", 4))
	tmpFile := useTestConfig(configText)
	defer os.Remove(tmpFile.Name())

	logger, _ := zap.NewDevelopment()

	config := initConfig(logger.Sugar())
	gomega.Expect(config).ToNot(gomega.BeNil())

	gomega.Expect(config.ClientId).To(gomega.Equal("test-client-id"))
	gomega.Expect(config.WebhookSecret).To(gomega.Equal(""))
	gomega.Expect(config.ExpectedAudience).To(gomega.Equal("permissionizer-server (https://permissionizer.app)"))
	gomega.Expect(config.PrivateKey).NotTo(gomega.BeNil())
	gomega.Expect(config.RateLimit).To(gomega.Equal(types.RateLimitConfig{
		TokensPerMinute: 10.0,
		Overrides:       map[string]float64{},
	}))
	gomega.Expect(config.Unsecure.SkipTokenValidation).To(gomega.BeFalse())
}

func useTestConfig(configText string) *os.File {
	dir, err := os.MkdirTemp(os.TempDir(), "permissionizer-test")
	gomega.Expect(err).To(gomega.BeNil())

	tmpFile, err := os.Create(dir + "/permissionizer-server.yaml")
	if err != nil {
		panic(err)
	}

	_, err = tmpFile.WriteString(configText)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(tmpFile.Close()).To(gomega.BeNil())

	viper.AddConfigPath(path.Dir(tmpFile.Name()))

	return tmpFile
}

func reset() {
	viper.Reset()
}
