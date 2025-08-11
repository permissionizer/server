package util

import (
	"server/types"
	"sync"

	"golang.org/x/time/rate"
)

type RepoRateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	config   types.RateLimitConfig
}

func NewRepoRateLimiter(config types.RateLimitConfig) *RepoRateLimiter {
	return &RepoRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

func (r *RepoRateLimiter) GetLimiter(org string, repo string) *rate.Limiter {
	r.mu.RLock()
	limiter, exists := r.limiters[repo]
	r.mu.RUnlock()
	if exists {
		return limiter
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	limit := r.config.TokensPerMinute
	if override, ok := r.config.Overrides[repo]; ok {
		limit = override
	} else if override, ok := r.config.Overrides[org]; ok {
		limit = override
	}
	tokensPerSecond := limit / 60.
	limiter = rate.NewLimiter(rate.Limit(tokensPerSecond), int(limit))
	r.limiters[repo] = limiter
	return limiter
}
