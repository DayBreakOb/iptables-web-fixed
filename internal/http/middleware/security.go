package middleware

import (
	"github.com/gin-gonic/gin"
)

func SecurityHeaders(apiBase string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// 关键：允许页面连接到你的 API
		c.Header("Content-Security-Policy",
			"default-src 'self'; "+
				"connect-src 'self' "+apiBase+"; "+
				"img-src 'self' data: blob:; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"base-uri 'none'; frame-ancestors 'none'")
		c.Next()
	}
}
