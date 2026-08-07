package util

import (
	"testing"

	"github.com/onsi/gomega"
	"golang.org/x/time/rate"

	"server/types"
)

func TestDefaultLimit(t *testing.T) {
	gomega.RegisterTestingT(t)

	cfg := types.RateLimitConfig{
		TokensPerMinute: 10,
		Overrides:       map[string]float64{},
	}
	rl := NewRepoRateLimiter(cfg)

	limiter := rl.GetLimiter("org1", "repo1")

	gomega.Expect(limiter.Limit()).To(gomega.Equal(rate.Limit(10.0 / 60.0)))
	gomega.Expect(limiter.Burst()).To(gomega.Equal(10))
}

func TestRepoOverride(t *testing.T) {
	gomega.RegisterTestingT(t)

	cfg := types.RateLimitConfig{
		TokensPerMinute: 10,
		Overrides:       map[string]float64{"org1/repo1": 20},
	}
	rl := NewRepoRateLimiter(cfg)

	limiter := rl.GetLimiter("org1", "repo1")

	gomega.Expect(limiter.Limit()).To(gomega.Equal(rate.Limit(20.0 / 60.0)))
	gomega.Expect(limiter.Burst()).To(gomega.Equal(20))
}

func TestOrgOverride(t *testing.T) {
	gomega.RegisterTestingT(t)

	cfg := types.RateLimitConfig{
		TokensPerMinute: 10,
		Overrides:       map[string]float64{"org1": 30},
	}
	rl := NewRepoRateLimiter(cfg)

	limiter := rl.GetLimiter("org1", "repo1")

	gomega.Expect(limiter.Limit()).To(gomega.Equal(rate.Limit(30.0 / 60.0)))
	gomega.Expect(limiter.Burst()).To(gomega.Equal(30))
}

func TestLimiterCaching(t *testing.T) {
	gomega.RegisterTestingT(t)

	cfg := types.RateLimitConfig{
		TokensPerMinute: 10,
	}
	rl := NewRepoRateLimiter(cfg)

	lim1 := rl.GetLimiter("org1", "repo1")
	lim2 := rl.GetLimiter("org1", "repo1")

	gomega.Expect(lim1).To(gomega.BeIdenticalTo(lim2))
}

func TestLimiterCachingPerRepo(t *testing.T) {
	gomega.RegisterTestingT(t)

	cfg := types.RateLimitConfig{
		TokensPerMinute: 10,
	}
	rl := NewRepoRateLimiter(cfg)

	lim1 := rl.GetLimiter("org1", "repo1")
	lim2 := rl.GetLimiter("org1", "repo2")

	gomega.Expect(lim1).ToNot(gomega.BeIdenticalTo(lim2))
}

func TestTokenConsumption(t *testing.T) {
	gomega.RegisterTestingT(t)

	cfg := types.RateLimitConfig{
		TokensPerMinute: 2, // 1 token every 30s
	}
	rl := NewRepoRateLimiter(cfg)

	limiter := rl.GetLimiter("org1", "repo1")

	// burst = 2, so both should pass immediately
	gomega.Expect(limiter.Allow()).To(gomega.BeTrue())
	gomega.Expect(limiter.Allow()).To(gomega.BeTrue())

	// now bucket is empty, next should fail
	gomega.Expect(limiter.Allow()).To(gomega.BeFalse())
}

func TestStartsFull(t *testing.T) {
	gomega.RegisterTestingT(t)

	cfg := types.RateLimitConfig{
		TokensPerMinute: 5,
	}
	rl := NewRepoRateLimiter(cfg)

	limiter := rl.GetLimiter("org1", "repo1")

	// All tokens should be available immediately
	for i := 0; i < 5; i++ {
		gomega.Expect(limiter.Allow()).To(gomega.BeTrue(), "token %d should be available at start", i+1)
	}
	// Next one should fail
	gomega.Expect(limiter.Allow()).To(gomega.BeFalse())
}
