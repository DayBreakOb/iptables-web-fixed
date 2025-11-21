package router

import (
	"iptables-web/backend/internal/http/handlers"
	"iptables-web/backend/internal/http/middleware"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine) {
	// 全局中间件：日志/恢复 -> CORS（放最前）
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(middleware.CORS(
		"http://localhost:8080", // 按你的前端实际 Origin 改
		"http://localhost:5173",
	))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	// ---------- API 组（不要加 CSP！） ----------
	api := r.Group("/api")
	{

		hosts := handlers.NewHostsHandler()

		api.GET("/hosts", hosts.List)
		api.GET("/hosts/:id", hosts.Get)
		api.POST("/hosts", hosts.Create)
		api.PUT("/hosts/:id", hosts.Update)
		api.DELETE("/hosts/:id", hosts.Delete)
		api.POST("/hosts/batch-delete", hosts.BatchDelete)
		rules := handlers.NewRulesHandler()
		api.GET("/rules/current", rules.GetCurrentRules)
		api.GET("/rules/currentview", rules.GetCurrentRulesView)
		ops := handlers.NewRulesOpsHandler()
		api.POST("/rules/flush", ops.Flush)                       // 清空表/链
		api.POST("/rules/zero", ops.Zero)                         // 清零计数（表/链）
		api.POST("/rules/clear-user-chains", ops.ClearUserChains) // -X
		api.GET("/rules/export", ops.Export)                      // iptables-save
		api.POST("/rules/import", ops.Import)                     // iptables-restore
		api.POST("/rules/append", ops.Append)                     // -A
		api.POST("/rules/insert", ops.Insert)                     // -I
		api.POST("/rules/delete", ops.Delete)
		ipt := handlers.NewIptablesHandler()
		api.GET("/hosts/:id/iptables/:family/:table/chains", ipt.ListChains)
		api.POST("/hosts/:id/iptables/:family/:table/chains", ipt.CreateChain)
		api.DELETE("/hosts/:id/iptables/:family/:table/chains/:chain", ipt.DeleteChain)

		api.GET("/hosts/:id/iptables/:family/:table/chains/:chain/rules", ipt.ListRules)
		api.POST("/hosts/:id/iptables/:family/:table/chains/:chain/rules", ipt.CreateRule)
		api.PUT("/hosts/:id/iptables/:family/:table/chains/:chain/rules/:ruleId", ipt.UpdateRule)
		api.DELETE("/hosts/:id/iptables/:family/:table/chains/:chain/rules/:ruleId", ipt.DeleteRule)
		api.DELETE("/hosts/:id/iptables/:family/:table/chains/:chain/rules", ipt.ClearChain)

	}

	// ---------- 页面组（只在这里加 CSP） ----------
	pages := r.Group("/")
	//pages.Use(middleware.SecurityHeaders("http://localhost:8088")) // 你的 API 基地址（CSP 的 connect-src 用）
	{
		// 根路径返回首页
		pages.GET("/", func(c *gin.Context) {
			c.File("./ui/dist/index.html")
		})
		// 精确挂静态目录（不要 /* 通配到根！）
		pages.Static("/assets", "./ui/dist/assets")
		pages.StaticFile("/favicon.ico", "./ui/dist/favicon.ico")
	}

	// ---------- SPA 回退（注意：挂在 Engine 上，不是 pages 上） ----------
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		// /api/* 的 404 仍然返回 404，不要吞掉
		if strings.HasPrefix(p, "/api/") {
			c.Status(http.StatusNotFound)
			return
		}
		// 其他未知路径回到前端首页（SPA history 模式）
		c.File("./ui/dist/index.html")
	})
}
