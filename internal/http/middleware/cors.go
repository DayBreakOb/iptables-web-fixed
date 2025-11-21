package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func CORS(allowOrigins ...string) gin.HandlerFunc {
	allowed := map[string]struct{}{}
	reflectAll := false
	for _, o := range allowOrigins {
		o = strings.TrimSpace(o)
		if o == "*" {
			reflectAll = true
			continue
		}
		if o != "" {
			allowed[o] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && (reflectAll || has(allowed, origin)) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			reqHdr := c.GetHeader("Access-Control-Request-Headers")
			if reqHdr == "" {
				reqHdr = "Content-Type, Authorization"
			}
			c.Header("Access-Control-Allow-Headers", reqHdr)
			c.Header("Access-Control-Max-Age", "86400")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent) // 204 预检放行
			return
		}
		c.Next()
	}
}
func has(m map[string]struct{}, k string) bool { _, ok := m[k]; return ok }
