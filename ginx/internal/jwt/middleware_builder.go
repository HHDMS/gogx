package jwt

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/slog"
	"net/http"
	"time"

	"github.com/ecodeclub/ekit/set"
)

// MiddlewareBuilder 创建一个校验登录的 middleware.
// ignorePath: 默认使用 func(path string) bool { return false } 也就是全部不忽略.

type MiddlewareBuilder[T any] struct {
	ignorePath func(path string) bool
	manager    *Management[T]
	nowFunc    func() time.Time
}

func newMiddlewareBuilder[T any](m *Management[T]) *MiddlewareBuilder[T] {
	return &MiddlewareBuilder[T]{
		manager: m,
		ignorePath: func(path string) bool {
			return false
		},
		nowFunc: m.nowFunc,
	}
}

func (m *MiddlewareBuilder[T]) IgnorePath(path ...string) *MiddlewareBuilder[T] {
	return m.IgnorePathFunc(staticIgnorePaths(path...))
}

// IgnorePathFunc 设置忽略资源令牌认证的路径.
func (m *MiddlewareBuilder[T]) IgnorePathFunc(fn func(path string) bool) *MiddlewareBuilder[T] {
	m.ignorePath = fn
	return m
}

func (m *MiddlewareBuilder[T]) Build() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 无需校验
		if m.ignorePath(ctx.Request.URL.Path) {
			return
		}

		// 提取 token
		tokenStr := m.manager.extractTokenString(ctx)
		if tokenStr != "" {
			slog.Debug("failed to extract token")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// 校验 token
		clm, err := m.manager.VerifyAccessToken(tokenStr,
			jwt.WithTimeFunc(m.nowFunc))
		if err != nil {
			slog.Debug("access token verification failed")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		m.manager.setClaims(ctx, clm)
	}
}

// staticIgnorePaths 设置静态忽略的路径.
func staticIgnorePaths(paths ...string) func(path string) bool {
	s := set.NewMapSet[string](len(paths))
	for _, path := range paths {
		s.Add(path)
	}
	return func(path string) bool {
		return s.Exist(path)
	}
}
