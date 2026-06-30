package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"vpn-master/database"
	"vpn-master/models"
	"vpn-master/utils"

	"github.com/gin-gonic/gin"
)

func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func APIKeyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("X-API-Key")
		}
		if apiKey != database.GetSetting("api_key", "SuperSecretAdminKey123") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неавторизованный запрос."})
			c.Abort()
			return
		}
		c.Next()
	}
}

func SetupRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(CORS())

		r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "AimatosPanel API",
			"status":  "online",
			"version": "2.0.0",
		})
	})

		r.GET("/sub/:uuid", func(c *gin.Context) {
		uuid := c.Param("uuid")
		var u models.User
		var isActiveInt int
		var expiresAtStr *string

		err := database.DB.QueryRow(`SELECT id, name, is_active, vless_uuid, hysteria2_password, 
			traffic_limit_gb, traffic_used_bytes, expires_at, allowed_protocols, speed_limit_up_mbps, speed_limit_down_mbps 
			FROM users WHERE vless_uuid = ?`, uuid).Scan(
			&u.ID, &u.Name, &isActiveInt, &u.VlessUUID, &u.Hysteria2Password,
			&u.TrafficLimitGB, &u.TrafficUsedBytes, &expiresAtStr, &u.AllowedProtocols, &u.SpeedLimitUpMbps, &u.SpeedLimitDownMbps,
		)

		if err != nil || isActiveInt == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Подписка не найдена или деактивирована"})
			return
		}

		c.JSON(http.StatusOK, u)
	})

	api := r.Group("/")
	api.Use(APIKeyAuthMiddleware())
	{
				api.GET("/users", func(c *gin.Context) {
			rows, err := database.DB.Query("SELECT id, name, is_active, vless_uuid, hysteria2_password, traffic_limit_gb, traffic_used_bytes, traffic_uplink_bytes, traffic_downlink_bytes, speed_limit_up_mbps, speed_limit_down_mbps, allowed_protocols, expires_at FROM users")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()

			var users []models.User
			for rows.Next() {
				var u models.User
				var activeInt int
				var expStr *string
				if err := rows.Scan(&u.ID, &u.Name, &activeInt, &u.VlessUUID, &u.Hysteria2Password, &u.TrafficLimitGB, &u.TrafficUsedBytes, &u.TrafficUplinkBytes, &u.TrafficDownlinkBytes, &u.SpeedLimitUpMbps, &u.SpeedLimitDownMbps, &u.AllowedProtocols, &expStr); err == nil {
					u.IsActive = activeInt == 1
					users = append(users, u)
				}
			}
			c.JSON(http.StatusOK, users)
		})

		api.POST("/users", func(c *gin.Context) {
			var req struct {
				Name             string   `json:"name" binding:"required"`
				TrafficLimitGB   *float64 `json:"traffic_limit_gb"`
				DurationDays     *int     `json:"duration_days"`
				AllowedProtocols string   `json:"allowed_protocols"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			uuidStr := utils.GenerateUUID()
			pass, _ := utils.GeneratePassword(16)
			var expiresAt *string
			if req.DurationDays != nil && *req.DurationDays > 0 {
				formatted := time.Now().AddDate(0, 0, *req.DurationDays).Format("2006-01-02 15:04:05")
				expiresAt = &formatted
			}

			limitGB := 0.0
			if req.TrafficLimitGB != nil {
				limitGB = *req.TrafficLimitGB
			}

			_, err := database.DB.Exec(`INSERT INTO users (name, vless_uuid, hysteria2_password, traffic_limit_gb, expires_at, allowed_protocols) 
				VALUES (?, ?, ?, ?, ?, ?)`, req.Name, uuidStr, pass, limitGB, expiresAt, req.AllowedProtocols)
			if err != nil {
				c.JSON(http.StatusConflict, gin.H{"error": "Пользователь с таким именем уже существует"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"status": "ok", "name": req.Name, "vless_uuid": uuidStr, "hysteria2_password": pass})
		})

				api.GET("/settings", func(c *gin.Context) {
			rows, _ := database.DB.Query("SELECT key, value FROM settings")
			defer rows.Close()
			settings := make(map[string]string)
			for rows.Next() {
				var k, v string
				_ = rows.Scan(&k, &v)
				settings[k] = v
			}
			c.JSON(http.StatusOK, settings)
		})

		api.POST("/settings", func(c *gin.Context) {
			var req map[string]string
			if err := c.ShouldBindJSON(&req); err == nil {
				for k, v := range req {
					_, _ = database.DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", k, v)
				}
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			}
		})

		api.PUT("/users/:id", func(c *gin.Context) {
			id := c.Param("id")
			var req struct {
				Name             string  `json:"name" binding:"required"`
				TrafficLimitGB   float64 `json:"traffic_limit_gb"`
				AllowedProtocols string  `json:"allowed_protocols"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			_, err := database.DB.Exec("UPDATE users SET name = ?, traffic_limit_gb = ?, allowed_protocols = ? WHERE id = ?",
				req.Name, req.TrafficLimitGB, req.AllowedProtocols, id)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления базы данных"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

				api.DELETE("/users/:id", func(c *gin.Context) {
			id := c.Param("id")
			_, err := database.DB.Exec("DELETE FROM users WHERE id = ?", id)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить пользователя"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

				api.POST("/users/:id/toggle", func(c *gin.Context) {
			id := c.Param("id")
			_, err := database.DB.Exec("UPDATE users SET is_active = 1 - is_active WHERE id = ?", id)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка переключения активности"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

				api.POST("/users/bulk/toggle", func(c *gin.Context) {
			var req struct {
				IDs []int64 `json:"ids"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			for _, id := range req.IDs {
				_, _ = database.DB.Exec("UPDATE users SET is_active = 1 - is_active WHERE id = ?", id)
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

				api.POST("/users/bulk/delete", func(c *gin.Context) {
			var req struct {
				IDs []int64 `json:"ids"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			for _, id := range req.IDs {
				_, _ = database.DB.Exec("DELETE FROM users WHERE id = ?", id)
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

				api.POST("/users/bulk/reset", func(c *gin.Context) {
			var req struct {
				IDs []int64 `json:"ids"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			for _, id := range req.IDs {
				_, _ = database.DB.Exec("UPDATE users SET traffic_used_bytes = 0, traffic_uplink_bytes = 0, traffic_downlink_bytes = 0 WHERE id = ?", id)
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

				api.GET("/api/node/sync", func(c *gin.Context) {
			rowsS, _ := database.DB.Query("SELECT key, value FROM settings")
			defer rowsS.Close()
			settings := make(map[string]string)
			for rowsS.Next() {
				var k, v string
				_ = rowsS.Scan(&k, &v)
				settings[k] = v
			}

			rowsU, _ := database.DB.Query("SELECT id, name, is_active, vless_uuid, hysteria2_password, traffic_limit_gb, traffic_used_bytes, traffic_uplink_bytes, traffic_downlink_bytes, speed_limit_up_mbps, speed_limit_down_mbps, allowed_protocols, expires_at FROM users")
			defer rowsU.Close()
			var users []models.User
			for rowsU.Next() {
				var u models.User
				var activeInt int
				var expStr *string
				if err := rowsU.Scan(&u.ID, &u.Name, &activeInt, &u.VlessUUID, &u.Hysteria2Password, &u.TrafficLimitGB, &u.TrafficUsedBytes, &u.TrafficUplinkBytes, &u.TrafficDownlinkBytes, &u.SpeedLimitUpMbps, &u.SpeedLimitDownMbps, &u.AllowedProtocols, &expStr); err == nil {
					u.IsActive = activeInt == 1
					users = append(users, u)
				}
			}

			c.JSON(http.StatusOK, gin.H{
				"users":    users,
				"settings": settings,
			})
		})

		api.POST("/api/node/stats", func(c *gin.Context) {
			var stats []NodeStat
			if err := c.ShouldBindJSON(&stats); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			for _, stat := range stats {
				var query string
				if stat.Direction == "downlink" {
					query = "UPDATE users SET traffic_used_bytes = traffic_used_bytes + ?, traffic_downlink_bytes = traffic_downlink_bytes + ? WHERE name = ?"
				} else {
					query = "UPDATE users SET traffic_used_bytes = traffic_used_bytes + ?, traffic_uplink_bytes = traffic_uplink_bytes + ? WHERE name = ?"
				}
				_, _ = database.DB.Exec(query, stat.Bytes, stat.Bytes, stat.Username)
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		api.POST("/api/node/sysstats", func(c *gin.Context) {
			var sysStats SysStatsPayload
			if err := c.ShouldBindJSON(&sysStats); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			nodeID := c.GetHeader("X-Node-ID")
			if nodeID == "" {
				nodeID = c.ClientIP()
			}

			activeNodesMutex.Lock()
			activeNodes[nodeID] = &NodeInfo{
				ID:            nodeID,
				Name:          nodeID,
				IP:            c.ClientIP(),
				LastSeen:      time.Now(),
				CPUUsage:      sysStats.CPUUsage,
				RAMTotalBytes: sysStats.RAMTotalBytes,
				RAMPercent:    sysStats.RAMPercent,
				UptimeSeconds: sysStats.UptimeSeconds,
				Status:        "online",
			}
			activeNodesMutex.Unlock()

			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		api.GET("/api/nodes", func(c *gin.Context) {
			activeNodesMutex.RLock()
			defer activeNodesMutex.RUnlock()

			var list []NodeInfo
			now := time.Now()
			for _, node := range activeNodes {
				if now.Sub(node.LastSeen) > 30*time.Second {
					node.Status = "offline"
				}
				list = append(list, *node)
			}
			c.JSON(http.StatusOK, list)
		})

		api.GET("/api/stream/logs", func(c *gin.Context) {
			nodeID := c.Query("node_id")
			if nodeID != "" && nodeID != "master" {
				client := &http.Client{Timeout: 0}
				req, _ := http.NewRequestWithContext(c.Request.Context(), "GET", fmt.Sprintf("http://%s:8085/api/stream/logs", nodeID), nil)
				req.Header.Set("X-API-Key", database.GetSetting("api_key", ""))
				
				resp, err := client.Do(req)
				if err != nil {
					c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
					return
				}
				defer resp.Body.Close()

				c.Writer.Header().Set("Content-Type", "text/event-stream")
				reader := bufio.NewReader(resp.Body)
				for {
					line, err := reader.ReadBytes('\n')
					if err != nil {
						return
					}
					_, _ = c.Writer.Write(line)
					c.Writer.Flush()
				}
			}

			c.Writer.Header().Set("Content-Type", "text/event-stream")
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-c.Request.Context().Done():
					return
				case <-ticker.C:
					_, _ = fmt.Fprintf(c.Writer, ": ping\n\n")
					c.Writer.Flush()
				}
			}
		})
	}

		if _, err := os.Stat("./dist"); err == nil {
		r.Static("/assets", "./dist/assets")
		r.NoRoute(func(c *gin.Context) {
			path := c.Request.URL.Path
			if !strings.HasPrefix(path, "/api") &&
				!strings.HasPrefix(path, "/users") &&
				!strings.HasPrefix(path, "/settings") &&
				!strings.HasPrefix(path, "/sub") &&
				!strings.HasPrefix(path, "/health") {
				c.File("./dist/index.html")
				return
			}
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
		})
	} else {
		r.NoRoute(func(c *gin.Context) {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found (dist directory is missing)"})
		})
	}

	return r
}