package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"vpn-master/database"
	"vpn-master/models"
	"vpn-master/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

func getEmojiFlag(countryCode string) string {
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if len(countryCode) != 2 {
		return "🌐"
	}
	r1 := rune(countryCode[0]) - 'A' + 127462
	r2 := rune(countryCode[1]) - 'A' + 127462
	return string(r1) + string(r2)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type Claims struct {
	AdminID     int64    `json:"admin_id"`
	Username    string   `json:"username"`
	RoleID      int64    `json:"role_id"`
	RoleName    string   `json:"role_name"`
	Permissions []string `json:"permissions"`
	IsRoot      bool     `json:"is_root"`
	jwt.RegisteredClaims
}

var (
	failedAttempts = make(map[string]int)
	lockoutTimes   = make(map[string]time.Time)
	rateLimitMu    sync.Mutex
	usernameRegex  = regexp.MustCompile(`^[a-z0-9_]{3,30}$`)
)

func (nc *NodeConn) WriteJSON(msgType string, payload interface{}) error {
	nc.Mu.Lock()
	defer nc.Mu.Unlock()
	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg := WSMessage{
		Type:    msgType,
		Payload: bytes,
	}
	return nc.Conn.WriteJSON(msg)
}

func GetJwtSecret() []byte {
	sec := database.GetSetting("jwt_secret", "")
	if sec == "" {
		return []byte("AimatosPanelSuperSecretDefaultFallbackKey123!")
	}
	bytes, err := base64.StdEncoding.DecodeString(sec)
	if err != nil {
		return []byte(sec)
	}
	return bytes
}

func GenerateToken(adminID int64, username string, roleID int64, roleName string, permissions []string, isRoot bool) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		AdminID:     adminID,
		Username:    username,
		RoleID:      roleID,
		RoleName:    roleName,
		Permissions: permissions,
		IsRoot:      isRoot,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(GetJwtSecret())
}

func ParseToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return GetJwtSecret(), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func checkLoginRateLimit(ip string) (bool, time.Duration) {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	lockTime, exists := lockoutTimes[ip]
	if exists {
		if time.Now().Before(lockTime) {
			return true, time.Until(lockTime)
		}
		delete(lockoutTimes, ip)
		delete(failedAttempts, ip)
	}
	return false, 0
}

func recordFailedLogin(ip string) {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	failedAttempts[ip]++
	if failedAttempts[ip] >= 5 {
		lockoutTimes[ip] = time.Now().Add(15 * time.Minute)
	}
}

func clearFailedLogins(ip string) {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	delete(failedAttempts, ip)
	delete(lockoutTimes, ip)
}

func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "null")
		}
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

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://cdnjs.cloudflare.com; connect-src 'self' ws: wss: http: https:;")
		c.Next()
	}
}

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен не предоставлен"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный формат заголовка авторизации"})
			c.Abort()
			return
		}

		claims, err := ParseToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Сессия устарела или токен недействителен"})
			c.Abort()
			return
		}

		c.Set("admin_id", claims.AdminID)
		c.Set("username", claims.Username)
		c.Set("role_id", claims.RoleID)
		c.Set("role_name", claims.RoleName)
		c.Set("permissions", claims.Permissions)
		c.Set("is_root", claims.IsRoot)
		c.Next()
	}
}

func RequirePermission(requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		isRootVal, exists := c.Get("is_root")
		if exists && isRootVal.(bool) {
			c.Next()
			return
		}

		if requiredPermission == "" {
			c.Next()
			return
		}

		permsVal, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Недостаточно прав"})
			c.Abort()
			return
		}

		permissions, ok := permsVal.([]string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Недостаточно прав"})
			c.Abort()
			return
		}

		hasPermission := false
		for _, perm := range permissions {
			if perm == requiredPermission {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{"error": "Недостаточно прав"})
			c.Abort()
			return
		}

		c.Next()
	}
}

type ipLimiter struct {
	tokens     float64
	lastAccess time.Time
}

var (
	subLimiterMap = make(map[string]*ipLimiter)
	subLimiterMu  sync.Mutex
)

func isRateLimited(ip string) bool {
	subLimiterMu.Lock()
	defer subLimiterMu.Unlock()

	limiter, exists := subLimiterMap[ip]
	now := time.Now()
	if !exists {
		subLimiterMap[ip] = &ipLimiter{
			tokens:     5,
			lastAccess: now,
		}
		return false
	}

	elapsed := now.Sub(limiter.lastAccess).Seconds()
	limiter.tokens += elapsed * (1.0 / 10.0)
	if limiter.tokens > 5 {
		limiter.tokens = 5
	}
	limiter.lastAccess = now

	if limiter.tokens < 1 {
		return true
	}

	limiter.tokens -= 1
	return false
}

func parseAndDeriveIP(uuidStr, subnetCIDR string) string {
	defaultIP := "10.8.0.45"
	_, ipNet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return defaultIP
	}

	hasher := sha256.New()
	hasher.Write([]byte(uuidStr))
	seed := hasher.Sum(nil)

	ip := ipNet.IP.To4()
	if ip == nil {
		return defaultIP
	}

	mask := ipNet.Mask
	result := make([]byte, 4)
	copy(result, ip)

	for i := 0; i < 4; i++ {
		hostBits := ^mask[i]
		if hostBits > 0 {
			seedByte := seed[i%len(seed)]
			if hostBits == 255 {
				val := (int(seedByte) % 250) + 3
				result[i] = byte(val)
			} else {
				result[i] = (result[i] & mask[i]) | (seedByte & hostBits)
				if result[3] == 0 {
					result[3] = 3
				}
				if result[3] == 255 {
					result[3] = 254
				}
			}
		}
	}

	return net.IP(result).String()
}

func deriveWireguardKeys(uuidStr, subnetCIDR string) (clientIP string, clientPrivate string, clientPublic string) {
	clientIP = parseAndDeriveIP(uuidStr, subnetCIDR)

	hasher := sha256.New()
	hasher.Write([]byte(uuidStr))
	seed := hasher.Sum(nil)

	curve := ecdh.X25519()
	privBytes := make([]byte, 32)
	copy(privBytes, seed[:32])
	privBytes[0] &= 248
	privBytes[31] &= 127
	privBytes[31] |= 64

	privKey, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return clientIP, "", ""
	}
	pubKey := privKey.PublicKey()

	clientPrivate = base64.StdEncoding.EncodeToString(privBytes)
	clientPublic = base64.StdEncoding.EncodeToString(pubKey.Bytes())
	return
}

func getSyncDataForNode(nodeID string, nodeIP string) (map[string]interface{}, error) {
	var nodeIPFound, nodeName, locationCode, locationName, fallbackAction, customDNS, settingsJSON string
	var vlessPort, vlessGrpcPort, hysteriaPort, tuicPort, naivePort, wgPort, ssPort, fallbackSpeedLimit int

	errNode := database.DB.QueryRow(`SELECT ip, name, location_code, location_name, 
		vless_port, vless_grpc_port, hysteria_port, tuic_port, naive_port, wireguard_port, shadowsocks_port,
		fallback_action, fallback_speed_limit, custom_dns, settings_json 
		FROM nodes WHERE id = ? OR ip = ?`, nodeID, nodeIP).Scan(
		&nodeIPFound, &nodeName, &locationCode, &locationName,
		&vlessPort, &vlessGrpcPort, &hysteriaPort, &tuicPort, &naivePort, &wgPort, &ssPort,
		&fallbackAction, &fallbackSpeedLimit, &customDNS, &settingsJSON,
	)

	if errNode != nil {
		return nil, errNode
	}

	settings := make(map[string]string)
	rowsSettings, errS := database.DB.Query("SELECT key, value FROM settings")
	if errS == nil {
		for rowsSettings.Next() {
			var k, v string
			if errScan := rowsSettings.Scan(&k, &v); errScan == nil {
				settings[k] = v
			}
		}
		rowsSettings.Close()
	}
	if settingsJSON != "" && settingsJSON != "{}" {
		var overrides map[string]string
		if errUnmarshal := json.Unmarshal([]byte(settingsJSON), &overrides); errUnmarshal == nil {
			for k, v := range overrides {
				settings[k] = v
			}
		}
	}
	settings["server_ip"] = nodeIP
	settings["server_location"] = getEmojiFlag(locationCode) + " " + locationName
	settings["vless_port"] = fmt.Sprintf("%d", vlessPort)
	settings["vless_grpc_port"] = fmt.Sprintf("%d", vlessGrpcPort)
	settings["hysteria_port"] = fmt.Sprintf("%d", hysteriaPort)
	settings["tuic_port"] = fmt.Sprintf("%d", tuicPort)
	settings["naive_port"] = fmt.Sprintf("%d", naivePort)
	settings["wireguard_port"] = fmt.Sprintf("%d", wgPort)
	settings["shadowsocks_port"] = fmt.Sprintf("%d", ssPort)
	settings["node_fallback_action"] = fallbackAction
	settings["node_fallback_speed"] = fmt.Sprintf("%d", fallbackSpeedLimit)
	settings["custom_dns"] = customDNS

	rowsU, _ := database.DB.Query(`SELECT id, name, is_active, vless_uuid, hysteria2_password, 
		traffic_limit_gb, traffic_used_bytes, traffic_uplink_bytes, traffic_downlink_bytes, 
		speed_limit_up_mbps, speed_limit_down_mbps, allowed_protocols, expires_at, device_limit, fallback_action, fallback_speed_limit FROM users`)
	defer rowsU.Close()

	type NodeUserPayload struct {
		models.User
		AuthorizedIPs []string `json:"authorized_ips"`
	}

	var users []NodeUserPayload
	for rowsU.Next() {
		var u models.User
		var activeInt int
		var expStr *string
		err := rowsU.Scan(&u.ID, &u.Name, &activeInt, &u.VlessUUID, &u.Hysteria2Password,
			&u.TrafficLimitGB, &u.TrafficUsedBytes, &u.TrafficUplinkBytes, &u.TrafficDownlinkBytes,
			&u.SpeedLimitUpMbps, &u.SpeedLimitDownMbps, &u.AllowedProtocols, &expStr,
			&u.DeviceLimit, &u.FallbackAction, &u.FallbackSpeedLimit)
		if err == nil {
			u.IsActive = activeInt == 1

			var ips []string
			rowsI, errI := database.DB.Query(`SELECT ip_address FROM user_devices 
				WHERE user_id = ? AND last_seen > datetime('now', '-15 minutes')`, u.ID)
			if errI == nil {
				for rowsI.Next() {
					var ip string
					if errS := rowsI.Scan(&ip); errS == nil {
						ips = append(ips, ip)
					}
				}
				rowsI.Close()
			}

			users = append(users, NodeUserPayload{
				User:          u,
				AuthorizedIPs: ips,
			})
		}
	}

	return map[string]interface{}{
		"users":    users,
		"settings": settings,
	}, nil
}

func SyncNode(nodeKey string) {
	NodeConnMutex.RLock()
	nc, exists := NodeConnections[nodeKey]
	NodeConnMutex.RUnlock()

	if exists {
		var nodeIP string
		err := database.DB.QueryRow("SELECT ip FROM nodes WHERE id = ?", nodeKey).Scan(&nodeIP)
		if err == nil {
			payload, err := getSyncDataForNode(nodeKey, nodeIP)
			if err == nil {
				_ = nc.WriteJSON("sync", payload)
			}
		}
	}
}

func SyncAllNodes() {
	NodeConnMutex.RLock()
	keys := make([]string, 0, len(NodeConnections))
	for k := range NodeConnections {
		keys = append(keys, k)
	}
	NodeConnMutex.RUnlock()

	for _, k := range keys {
		go SyncNode(k)
	}
}

func SetupRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(CORS())
	r.Use(SecurityHeaders())

	var jwtSecret string
	_ = database.DB.QueryRow("SELECT value FROM settings WHERE key = 'jwt_secret'").Scan(&jwtSecret)
	if jwtSecret == "" {
		bytes := make([]byte, 32)
		_, _ = rand.Read(bytes)
		jwtSecret = base64.StdEncoding.EncodeToString(bytes)
		_, _ = database.DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('jwt_secret', ?)", jwtSecret)
	}

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "AimatosPanel Headless API",
			"status":  "online",
			"version": "3.0.0",
		})
	})

	r.POST("/api/auth/login", handleLogin)
	r.GET("/sub/:uuid", handleSubscription)
	r.GET("/api/node/ws", handleNodeWebSocket)

	api := r.Group("/")
	api.Use(JWTAuthMiddleware())
	{
		api.GET("/users", RequirePermission("clients:read"), handleGetUsers)
		api.POST("/users", RequirePermission("clients:write"), handleCreateUser)
		api.PUT("/users/:id", RequirePermission("clients:write"), handleUpdateUser)
		api.DELETE("/users/:id", RequirePermission("clients:write"), handleDeleteUser)
		api.POST("/users/:id/toggle", RequirePermission("clients:write"), handleToggleUser)

		api.POST("/users/bulk/toggle", RequirePermission("clients:write"), handleBulkToggleRoute)
		api.POST("/users/bulk/delete", RequirePermission("clients:write"), handleBulkDeleteRoute)
		api.POST("/users/bulk/reset", RequirePermission("clients:write"), handleBulkResetRoute)

		api.GET("/api/nodes", RequirePermission("nodes:read"), handleGetNodes)
		api.POST("/api/nodes", RequirePermission("nodes:write"), handleCreateNode)
		api.PUT("/api/nodes/:id", RequirePermission("nodes:write"), handleUpdateNode)
		api.DELETE("/api/nodes/:id", RequirePermission("nodes:write"), handleDeleteNode)
		api.GET("/api/node/status", RequirePermission("nodes:read"), handleGetNodeStatus)

		api.GET("/settings", RequirePermission("settings:read"), handleGetSettings)
		api.POST("/settings", RequirePermission("settings:write"), handleSaveSettings)
		api.GET("/api/logs", RequirePermission("logs:read"), handleGetLogs)
		api.GET("/api/stream/logs", RequirePermission("logs:read"), handleStreamLogs)

		api.GET("/api/active-sessions", RequirePermission("nodes:read"), handleGetActiveSessions)
		api.POST("/api/active-sessions/kill", RequirePermission("nodes:write"), handleKillSession)

		api.GET("/api/admins", RequirePermission("admins:manage"), handleGetAdmins)
		api.POST("/api/admins", RequirePermission("admins:manage"), handleCreateAdmin)
		api.PUT("/api/admins/:id", RequirePermission("admins:manage"), handleUpdateAdmin)
		api.DELETE("/api/admins/:id", RequirePermission("admins:manage"), handleDeleteAdmin)
		
		api.GET("/api/roles", RequirePermission("admins:manage"), handleGetRoles)
	}

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
	})

	return r
}

func handleLogin(c *gin.Context) {
	clientIP := c.ClientIP()

	if locked, duration := checkLoginRateLimit(clientIP); locked {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": fmt.Sprintf("Слишком много попыток входа. Блокировка на %s", duration.Round(time.Second))})
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Заполните все поля"})
		return
	}

	var id int64
	var hash, roleName, permissionsStr string
	var roleID int64
	var isRoot int
	
	err := database.DB.QueryRow(`
		SELECT a.id, a.password_hash, a.role_id, a.is_root, r.name, r.permissions 
		FROM admins a 
		JOIN roles r ON a.role_id = r.id 
		WHERE a.username = ?`, req.Username).Scan(&id, &hash, &roleID, &isRoot, &roleName, &permissionsStr)
		
	if err != nil || !utils.CheckPasswordHash(req.Password, hash) {
		recordFailedLogin(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный логин или пароль"})
		return
	}

	clearFailedLogins(clientIP)

	permissions := strings.Split(permissionsStr, ",")
	isRootBool := isRoot == 1

	token, err := GenerateToken(id, req.Username, roleID, roleName, permissions, isRootBool)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось выпустить сессию"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"username": req.Username,
		"role":     roleName,
	})
}

func handleGetAdmins(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT a.id, a.username, a.role_id, r.name, a.is_root, a.email, a.created_at 
		FROM admins a
		JOIN roles r ON a.role_id = r.id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var list []AdminPayload
	for rows.Next() {
		var a AdminPayload
		var isRootInt int
		if err := rows.Scan(&a.ID, &a.Username, &a.RoleID, &a.RoleName, &isRootInt, &a.Email, &a.CreatedAt); err == nil {
			a.IsRoot = isRootInt == 1
			list = append(list, a)
		}
	}
	c.JSON(http.StatusOK, list)
}

func handleGetRoles(c *gin.Context) {
	rows, err := database.DB.Query("SELECT id, name, permissions FROM roles")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type RolePayload struct {
		ID          int64    `json:"id"`
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}

	var list []RolePayload
	for rows.Next() {
		var id int64
		var name, permsStr string
		if err := rows.Scan(&id, &name, &permsStr); err == nil {
			list = append(list, RolePayload{
				ID:          id,
				Name:        name,
				Permissions: strings.Split(permsStr, ","),
			})
		}
	}
	c.JSON(http.StatusOK, list)
}

func handleCreateAdmin(c *gin.Context) {
	isCurrentRoot := c.GetBool("is_root")
	var currentAdminPerms []string
	if permsRaw, exists := c.Get("permissions"); exists {
		if slice, ok := permsRaw.([]string); ok {
			currentAdminPerms = slice
		}
	}

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		RoleID   int64  `json:"role_id" binding:"required"`
		Email    string `json:"email" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Заполните все обязательные поля"})
		return
	}

	if !usernameRegex.MatchString(req.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Логин должен быть латиницей от 3 до 30 символов"})
		return
	}

	var rolePermsStr string
	err := database.DB.QueryRow("SELECT permissions FROM roles WHERE id = ?", req.RoleID).Scan(&rolePermsStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Роль не существует"})
		return
	}

	if !isCurrentRoot {
		targetPerms := strings.Split(rolePermsStr, ",")
		for _, tp := range targetPerms {
			hasIt := false
			for _, cp := range currentAdminPerms {
				if cp == tp {
					hasIt = true
					break
				}
			}
			if !hasIt {
				c.JSON(http.StatusForbidden, gin.H{"error": "Запрещено выдавать права, которых у вас нет"})
				return
			}
		}
	}

	hashed, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка шифрования"})
		return
	}

	_, err = database.DB.Exec("INSERT INTO admins (username, password_hash, role_id, is_root, email) VALUES (?, ?, ?, ?, ?)",
		req.Username, string(hashed), req.RoleID, 0, req.Email)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Пользователь с таким именем или Email уже существует"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleUpdateAdmin(c *gin.Context) {
	id := c.Param("id")
	currentAdminID := c.GetInt64("admin_id")
	isCurrentRoot := c.GetBool("is_root")
	
	var currentAdminPerms []string
	if permsRaw, exists := c.Get("permissions"); exists {
		if slice, ok := permsRaw.([]string); ok {
			currentAdminPerms = slice
		}
	}

	var isTargetRoot int
	var targetID int64
	err := database.DB.QueryRow("SELECT id, is_root FROM admins WHERE id = ?", id).Scan(&targetID, &isTargetRoot)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Администратор не найден"})
		return
	}

	if isTargetRoot == 1 && currentAdminID != targetID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Действие запрещено: Root неприкосновенен!"})
		return
	}

	var req struct {
		Username string `json:"username"`
		RoleID   int64  `json:"role_id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Username != "" && !usernameRegex.MatchString(req.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Недопустимый формат логина"})
		return
	}

	if req.RoleID != 0 {
		var rolePermsStr string
		err = database.DB.QueryRow("SELECT permissions FROM roles WHERE id = ?", req.RoleID).Scan(&rolePermsStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Роль не существует"})
			return
		}

		if !isCurrentRoot {
			targetPerms := strings.Split(rolePermsStr, ",")
			for _, tp := range targetPerms {
				hasIt := false
				for _, cp := range currentAdminPerms {
					if cp == tp {
						hasIt = true
						break
					}
				}
				if !hasIt {
					c.JSON(http.StatusForbidden, gin.H{"error": "Запрещено выдавать не принадлежащие вам права"})
					return
				}
			}
		}
	}

	if isTargetRoot == 1 && req.RoleID != 0 {
		var roleName string
		_ = database.DB.QueryRow("SELECT name FROM roles WHERE id = ?", req.RoleID).Scan(&roleName)
		if roleName != "Root Role" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Root должен сохранить Root Role"})
			return
		}
	}

	if req.Password != "" {
		hashed, _ := utils.HashPassword(req.Password)
		if req.RoleID != 0 {
			_, err = database.DB.Exec("UPDATE admins SET username = ?, role_id = ?, email = ?, password_hash = ? WHERE id = ?",
				req.Username, req.RoleID, req.Email, string(hashed), id)
		} else {
			_, err = database.DB.Exec("UPDATE admins SET username = ?, email = ?, password_hash = ? WHERE id = ?",
				req.Username, req.Email, string(hashed), id)
		}
	} else {
		if req.RoleID != 0 {
			_, err = database.DB.Exec("UPDATE admins SET username = ?, role_id = ?, email = ? WHERE id = ?",
				req.Username, req.RoleID, req.Email, id)
		} else {
			_, err = database.DB.Exec("UPDATE admins SET username = ?, email = ? WHERE id = ?",
				req.Username, req.Email, id)
		}
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleDeleteAdmin(c *gin.Context) {
	id := c.Param("id")
	currentAdminID := c.GetInt64("admin_id")

	var isTargetRoot int
	var targetID int64
	err := database.DB.QueryRow("SELECT id, is_root FROM admins WHERE id = ?", id).Scan(&targetID, &isTargetRoot)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Администратор не найден"})
		return
	}

	if targetID == currentAdminID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Вы не можете удалить себя"})
		return
	}

	if isTargetRoot == 1 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Действие запрещено: Root неприкосновенен!"})
		return
	}

	_, err = database.DB.Exec("DELETE FROM admins WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleSubscription(c *gin.Context) {
	clientIP := c.ClientIP()
	if isRateLimited(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Превышена частота запросов подписки."})
		return
	}

	uuid := c.Param("uuid")
	var u models.User
	var isActiveInt int
	var expiresAtStr *string

	err := database.DB.QueryRow(`SELECT id, name, is_active, vless_uuid, hysteria2_password, 
		traffic_limit_gb, traffic_used_bytes, traffic_uplink_bytes, traffic_downlink_bytes, expires_at, allowed_protocols, speed_limit_up_mbps, speed_limit_down_mbps, note, device_limit, fallback_action, fallback_speed_limit 
		FROM users WHERE vless_uuid = ?`, uuid).Scan(
		&u.ID, &u.Name, &isActiveInt, &u.VlessUUID, &u.Hysteria2Password,
		&u.TrafficLimitGB, &u.TrafficUsedBytes, &u.TrafficUplinkBytes, &u.TrafficDownlinkBytes, &expiresAtStr, &u.AllowedProtocols, &u.SpeedLimitUpMbps, &u.SpeedLimitDownMbps,
		&u.Note, &u.DeviceLimit, &u.FallbackAction, &u.FallbackSpeedLimit,
	)

	if err != nil || isActiveInt == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Подписка не найдена или неактивна"})
		return
	}

	hwid := c.Query("hwid")
	if hwid != "" {
		_, _ = database.DB.Exec(`
			INSERT OR REPLACE INTO user_devices (user_id, hwid, ip_address, last_seen)
			VALUES (?, ?, ?, datetime('now', 'localtime'))`,
			u.ID, hwid, clientIP)
	}

	brandName := database.GetSetting("brand_name", "AimatosPanel")
	realitySNI := database.GetSetting("reality_sni", "microsoft.com")
	realityPubKey := database.GetSetting("reality_public_key", "")
	realityShortID := database.GetSetting("reality_short_id", "")
	hysteriaObfs := database.GetSetting("hysteria_obfs", "ObfsSecretPass123")
	
	wgServerPubKey := database.GetSetting("wireguard_public_key", "")
	wgSubnet := database.GetSetting("wireguard_subnet", "10.8.0.0/24")
	wgMtu := database.GetSetting("wireguard_mtu", "1420")
	wgDns := database.GetSetting("wireguard_dns", "1.1.1.1, 10.8.0.1")
	ssMethod := database.GetSetting("shadowsocks_method", "2022-blake3-aes-128-gcm")
	rowsN, errN := database.DB.Query("SELECT id, ip, name, location_code, location_name, vless_port, vless_grpc_port, hysteria_port, tuic_port, naive_port, wireguard_port, shadowsocks_port, settings_json FROM nodes")
	if errN != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		return
	}
	defer rowsN.Close()

	type TargetNode struct {
		ID           int64
		IP           string
		Name         string
		LocationCode string
		LocationName string
		VlessPort    int
		VlessGrpcPort int
		HysteriaPort int
		TuicPort     int
		NaivePort    int
		WgPort       int
		SsPort       int
		SettingsJSON string
	}

	var onlineNodes []TargetNode
	activeNodesMutex.RLock()
	now := time.Now()
	for rowsN.Next() {
		var tn TargetNode
		err := rowsN.Scan(&tn.ID, &tn.IP, &tn.Name, &tn.LocationCode, &tn.LocationName,
			&tn.VlessPort, &tn.VlessGrpcPort, &tn.HysteriaPort, &tn.TuicPort, &tn.NaivePort, &tn.WgPort, &tn.SsPort, &tn.SettingsJSON)
		if err == nil {
			nodeKey := fmt.Sprintf("%d", tn.ID)
			if telemetryNode, exists := activeNodes[nodeKey]; exists {
				if now.Sub(telemetryNode.LastSeen) <= 30*time.Second {
					onlineNodes = append(onlineNodes, tn)
				}
			}
		}
	}
	activeNodesMutex.RUnlock()

	if len(onlineNodes) == 0 {
		rowsN2, _ := database.DB.Query("SELECT id, ip, name, location_code, location_name, vless_port, vless_grpc_port, hysteria_port, tuic_port, naive_port, wireguard_port, shadowsocks_port, settings_json FROM nodes")
		defer rowsN2.Close()
		for rowsN2.Next() {
			var tn TargetNode
			_ = rowsN2.Scan(&tn.ID, &tn.IP, &tn.Name, &tn.LocationCode, &tn.LocationName,
				&tn.VlessPort, &tn.VlessGrpcPort, &tn.HysteriaPort, &tn.TuicPort, &tn.NaivePort, &tn.WgPort, &tn.SsPort, &tn.SettingsJSON)
			onlineNodes = append(onlineNodes, tn)
		}
	}

	var links []string
	var activeWgConfig string
	var activeSsLink string
	var firstVlessTCP, firstVlessGRPC, firstHy2, firstNaive string
	allowedProtos := u.AllowedProtocols

	notePart := ""
	if u.Note != "" {
		notePart = fmt.Sprintf(" (%s)", u.Note)
	}

	for _, node := range onlineNodes {
		serverHost := node.IP
		serverLocation := getEmojiFlag(node.LocationCode) + " " + node.LocationName
		nodeOverrides := make(map[string]string)
		if node.SettingsJSON != "" && node.SettingsJSON != "{}" {
			_ = json.Unmarshal([]byte(node.SettingsJSON), &nodeOverrides)
		}
		getVal := func(key, fallback string) string {
			if val, exists := nodeOverrides[key]; exists {
				return val
			}
			return database.GetSetting(key, fallback)
		}

		enableVlessTcp := getVal("enable_vless_tcp_reality", "1") == "1"
		enableVlessGrpc := getVal("enable_vless_grpc_reality", "1") == "1"
		enableVlessH2 := getVal("enable_vless_h2_reality", "1") == "1"
		enableVlessQuic := getVal("enable_vless_quic_reality", "1") == "1"
		enableVlessHttpUpgrade := getVal("enable_vless_httpupgrade_reality", "1") == "1"
		enableVlessWs := getVal("enable_vless_ws_reality", "1") == "1"
		enableVlessXtls := getVal("enable_vless_xtls_vision", "1") == "1"
		
		enableVmessWs := getVal("enable_vmess_ws_tls", "1") == "1"
		enableVmessGrpc := getVal("enable_vmess_grpc", "1") == "1"
		enableVmessHttpUpgrade := getVal("enable_vmess_httpupgrade", "1") == "1"
		enableVmessReality := getVal("enable_vmess_reality", "1") == "1"

		enableTrojanReality := getVal("enable_trojan_reality", "1") == "1"
		enableTrojanGrpc := getVal("enable_trojan_grpc", "1") == "1"
		enableTrojanWs := getVal("enable_trojan_ws_tls", "1") == "1"

		enableWg := getVal("enable_wireguard", "1") == "1"
		enableSs := getVal("enable_shadowsocks", "1") == "1"
		enableSocks5 := getVal("enable_socks5_tls", "1") == "1"
		enableHttp := getVal("enable_http_tls", "1") == "1"
		enableNaive := getVal("enable_naive", "1") == "1"

		vlessH2Port, _ := strconv.Atoi(getVal("port_vless_h2_reality", "8450"))
		vlessQuicPort, _ := strconv.Atoi(getVal("port_vless_quic_reality", "8451"))
		vlessHttpUpgradePort, _ := strconv.Atoi(getVal("port_vless_httpupgrade_reality", "8452"))
		vlessWsPort, _ := strconv.Atoi(getVal("port_vless_ws_reality", "8453"))
		vlessXtlsPort, _ := strconv.Atoi(getVal("port_vless_xtls_vision", "8454"))

		vmessWsPort, _ := strconv.Atoi(getVal("port_vmess_ws_tls", "8455"))
		vmessGrpcPort, _ := strconv.Atoi(getVal("port_vmess_grpc", "8456"))
		vmessHttpUpgradePort, _ := strconv.Atoi(getVal("port_vmess_httpupgrade", "8457"))
		vmessRealityPort, _ := strconv.Atoi(getVal("port_vmess_reality", "8458"))

		trojanRealityPort, _ := strconv.Atoi(getVal("port_trojan_reality", "8459"))
		trojanGrpcPort, _ := strconv.Atoi(getVal("port_trojan_grpc", "8460"))
		trojanWsPort, _ := strconv.Atoi(getVal("port_trojan_ws_tls", "8461"))

		socks5Port, _ := strconv.Atoi(getVal("port_socks5_tls", "8462"))
		httpPort, _ := strconv.Atoi(getVal("port_http_tls", "8463"))
		naivePortVal, _ := strconv.Atoi(getVal("port_naive", "8446"))
		if strings.Contains(allowedProtos, "vless") {
			if enableVlessTcp {
				vlessTCP := fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp&flow=xtls-rprx-vision#%s | %s - VLESS TCP%s",
					u.VlessUUID, serverHost, node.VlessPort, realitySNI, realityPubKey, realityShortID, serverLocation, brandName, notePart)
				links = append(links, vlessTCP)
				if firstVlessTCP == "" {
					firstVlessTCP = vlessTCP
				}
			}
			if enableVlessGrpc {
				vlessGRPC := fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=grpc&serviceName=grpc-service#%s | %s - VLESS gRPC%s",
					u.VlessUUID, serverHost, node.VlessGrpcPort, realitySNI, realityPubKey, realityShortID, serverLocation, brandName, notePart)
				links = append(links, vlessGRPC)
				if firstVlessGRPC == "" {
					firstVlessGRPC = vlessGRPC
				}
			}
			if enableVlessH2 {
				links = append(links, fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=http&host=%s#%s | %s - VLESS HTTP/2%s",
					u.VlessUUID, serverHost, vlessH2Port, realitySNI, realityPubKey, realityShortID, realitySNI, serverLocation, brandName, notePart))
			}
			if enableVlessQuic {
				links = append(links, fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=quic#%s | %s - VLESS QUIC%s",
					u.VlessUUID, serverHost, vlessQuicPort, realitySNI, realityPubKey, realityShortID, serverLocation, brandName, notePart))
			}
			if enableVlessHttpUpgrade {
				links = append(links, fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=httpupgrade&path=/upgrade#%s | %s - VLESS HTTPUpgrade%s",
					u.VlessUUID, serverHost, vlessHttpUpgradePort, realitySNI, realityPubKey, realityShortID, serverLocation, brandName, notePart))
			}
			if enableVlessWs {
				links = append(links, fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=ws&path=/ws#%s | %s - VLESS WS%s",
					u.VlessUUID, serverHost, vlessWsPort, realitySNI, realityPubKey, realityShortID, serverLocation, brandName, notePart))
			}
			if enableVlessXtls {
				links = append(links, fmt.Sprintf("vless://%s@%s:%d?security=tls&sni=%s&flow=xtls-rprx-vision#%s | %s - VLESS XTLS Vision%s",
					u.VlessUUID, serverHost, vlessXtlsPort, realitySNI, serverLocation, brandName, notePart))
			}
		}

		if strings.Contains(allowedProtos, "hysteria2") {
			hy2 := fmt.Sprintf("hysteria2://%s@%s:%d?obfs=salamander&obfs-password=%s&insecure=1#%s | %s - Hysteria 2%s",
				u.Hysteria2Password, serverHost, node.HysteriaPort, hysteriaObfs, serverLocation, brandName, notePart)
			links = append(links, hy2)
			if firstHy2 == "" {
				firstHy2 = hy2
			}
		}
		if strings.Contains(allowedProtos, "vless") {
			if enableVmessWs {
				vj := map[string]interface{}{
					"v": "2", "ps": fmt.Sprintf("%s - VMess WS%s", brandName, notePart), "add": serverHost, "port": vmessWsPort,
					"id": u.VlessUUID, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "path": "/ws", "tls": "tls", "sni": realitySNI,
				}
				vjBytes, _ := json.Marshal(vj)
				links = append(links, "vmess://"+base64.StdEncoding.EncodeToString(vjBytes))
			}
			if enableVmessGrpc {
				vj := map[string]interface{}{
					"v": "2", "ps": fmt.Sprintf("%s - VMess gRPC%s", brandName, notePart), "add": serverHost, "port": vmessGrpcPort,
					"id": u.VlessUUID, "aid": "0", "scy": "auto", "net": "grpc", "type": "none", "path": "grpc-service", "tls": "tls", "sni": realitySNI,
				}
				vjBytes, _ := json.Marshal(vj)
				links = append(links, "vmess://"+base64.StdEncoding.EncodeToString(vjBytes))
			}
			if enableVmessHttpUpgrade {
				vj := map[string]interface{}{
					"v": "2", "ps": fmt.Sprintf("%s - VMess HTTPUpgrade%s", brandName, notePart), "add": serverHost, "port": vmessHttpUpgradePort,
					"id": u.VlessUUID, "aid": "0", "scy": "auto", "net": "httpupgrade", "type": "none", "path": "/upgrade", "tls": "tls", "sni": realitySNI,
				}
				vjBytes, _ := json.Marshal(vj)
				links = append(links, "vmess://"+base64.StdEncoding.EncodeToString(vjBytes))
			}
			if enableVmessReality {
				vj := map[string]interface{}{
					"v": "2", "ps": fmt.Sprintf("%s - VMess Reality%s", brandName, notePart), "add": serverHost, "port": vmessRealityPort,
					"id": u.VlessUUID, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "tls": "reality", "sni": realitySNI,
				}
				vjBytes, _ := json.Marshal(vj)
				links = append(links, "vmess://"+base64.StdEncoding.EncodeToString(vjBytes))
			}
		}
		if strings.Contains(allowedProtos, "hysteria2") {
			if enableTrojanReality {
				links = append(links, fmt.Sprintf("trojan://%s@%s:%d?security=reality&sni=%s&pbk=%s&sid=%s#%s | %s - Trojan Reality%s",
					u.Hysteria2Password, serverHost, trojanRealityPort, realitySNI, realityPubKey, realityShortID, serverLocation, brandName, notePart))
			}
			if enableTrojanGrpc {
				links = append(links, fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s&type=grpc&serviceName=grpc-service#%s | %s - Trojan gRPC%s",
					u.Hysteria2Password, serverHost, trojanGrpcPort, realitySNI, serverLocation, brandName, notePart))
			}
			if enableTrojanWs {
				links = append(links, fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s&type=ws&path=/ws#%s | %s - Trojan WS%s",
					u.Hysteria2Password, serverHost, trojanWsPort, realitySNI, serverLocation, brandName, notePart))
			}
		}

		if enableWg && strings.Contains(allowedProtos, "wireguard") && wgServerPubKey != "" {
			cliIP, cliPriv, _ := deriveWireguardKeys(u.VlessUUID, wgSubnet)
			wgConfig := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/24\nDNS = %s\nMTU = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25",
				cliPriv, cliIP, wgDns, wgMtu, wgServerPubKey, serverHost, node.WgPort)
			
			wgUri := fmt.Sprintf("wireguard://%s#%s | WG - %s%s",
				base64.StdEncoding.EncodeToString([]byte(wgConfig)), brandName, node.Name, notePart)
			
			links = append(links, wgUri)
			if activeWgConfig == "" {
				activeWgConfig = wgConfig
			}
		}

		if enableSs && strings.Contains(allowedProtos, "shadowsocks") {
			hasher := sha256.New()
			hasher.Write([]byte(u.Hysteria2Password))
			ssKey := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)[:16])
			rawCreds := fmt.Sprintf("%s:%s", ssMethod, ssKey)
			encodedCreds := base64.RawURLEncoding.EncodeToString([]byte(rawCreds))
			ssLink := fmt.Sprintf("ss://%s@%s:%d#%s | Shadowsocks - %s%s",
				encodedCreds, serverHost, node.SsPort, brandName, node.Name, notePart)
			
			links = append(links, ssLink)
			if activeSsLink == "" {
				activeSsLink = ssLink
			}
		}

		if enableSocks5 {
			links = append(links, fmt.Sprintf("socks5://%s:%s@%s:%d#%s | %s - Socks5 TLS%s",
				u.Name, u.Hysteria2Password, serverHost, socks5Port, serverLocation, brandName, notePart))
		}
		if enableHttp {
			links = append(links, fmt.Sprintf("http://%s:%s@%s:%d#%s | %s - HTTP TLS%s",
				u.Name, u.Hysteria2Password, serverHost, httpPort, serverLocation, brandName, notePart))
		}
		if enableNaive && strings.Contains(allowedProtos, "naive") {
			naiveUri := fmt.Sprintf("naive+https://%s:%s@%s:%d?padding=true#%s | %s - NaiveProxy%s",
				u.Name, u.Hysteria2Password, serverHost, naivePortVal, serverLocation, brandName, notePart)
			links = append(links, naiveUri)
			if firstNaive == "" {
				firstNaive = naiveUri
			}
		}
	}

	format := c.Query("format")

	if format == "json" {
		c.JSON(http.StatusOK, gin.H{
			"id":                     u.ID,
			"name":                   u.Name,
			"is_active":              isActiveInt == 1,
			"vless_uuid":             u.VlessUUID,
			"hysteria2_password":     u.Hysteria2Password,
			"traffic_limit_gb":       u.TrafficLimitGB,
			"traffic_used_bytes":     u.TrafficUsedBytes,
			"traffic_uplink_bytes":   u.TrafficUplinkBytes,
			"traffic_downlink_bytes": u.TrafficDownlinkBytes,
			"allowed_protocols":      u.AllowedProtocols,
			"expires_at":             expiresAtStr,
			"vless_tcp_link":         firstVlessTCP,
			"vless_grpc_link":        firstVlessGRPC,
			"hysteria_link":          firstHy2,
			"wireguard_config":       activeWgConfig,
			"shadowsocks_link":       activeSsLink,
			"naive_tls_link":         firstNaive,
			"brand_name":             brandName,
			"server_location":        brandName,
			"note":                   u.Note,
			"device_limit":           u.DeviceLimit,
			"fallback_action":        u.FallbackAction,
			"fallback_speed_limit":   u.FallbackSpeedLimit,
		})
		return
	}

	var expireTimeUnix int64 = 0
	if expiresAtStr != nil && *expiresAtStr != "" {
		t, err := time.Parse("2006-01-02 15:04:05", *expiresAtStr)
		if err == nil {
			expireTimeUnix = t.Unix()
		}
	}

	rawSubscription := strings.Join(links, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(rawSubscription))

	trafficLimitBytes := int64(u.TrafficLimitGB * 1073741824)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("profile-title", fmt.Sprintf("%s - %s", brandName, u.Name))
	c.Header("profile-update-interval", "24")
	c.Header("subscription-userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		u.TrafficUplinkBytes,
		u.TrafficDownlinkBytes,
		trafficLimitBytes,
		expireTimeUnix,
	))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-%s.txt\"", brandName, u.Name))
	c.String(http.StatusOK, encoded)
}

func handleGetActiveSessions(c *gin.Context) {
	activeNodesMutex.RLock()
	defer activeNodesMutex.RUnlock()

	type SessionResponse struct {
		NodeID   string                   `json:"node_id"`
		NodeName string                   `json:"node_name"`
		Sessions []ActiveConnInfo         `json:"sessions"`
	}

	var resp []SessionResponse
	for nodeID, node := range activeNodes {
		if time.Since(node.LastSeen) <= 30*time.Second {
			resp = append(resp, SessionResponse{
				NodeID:   nodeID,
				NodeName: node.Name,
				Sessions: node.ActiveConnections,
			})
		}
	}

	c.JSON(http.StatusOK, resp)
}

func handleKillSession(c *gin.Context) {
	var req struct {
		NodeID   string `json:"node_id" binding:"required"`
		Username string `json:"username" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные параметры запроса"})
		return
	}

	NodeConnMutex.RLock()
	nc, exists := NodeConnections[req.NodeID]
	NodeConnMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Узел отключен или недоступен"})
		return
	}

	err := nc.WriteJSON("kill_session", map[string]string{
		"username": req.Username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка передачи сигнала разрыва сессии"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Сигнал разрыва соединения отправлен на узел"})
}

func handleGetUsers(c *gin.Context) {
	rows, err := database.DB.Query(`SELECT id, name, is_active, vless_uuid, hysteria2_password, 
		traffic_limit_gb, traffic_used_bytes, traffic_uplink_bytes, traffic_downlink_bytes, 
		speed_limit_up_mbps, speed_limit_down_mbps, allowed_protocols, expires_at, note, device_limit, fallback_action, fallback_speed_limit FROM users`)
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
		err := rows.Scan(&u.ID, &u.Name, &activeInt, &u.VlessUUID, &u.Hysteria2Password,
			&u.TrafficLimitGB, &u.TrafficUsedBytes, &u.TrafficUplinkBytes, &u.TrafficDownlinkBytes,
			&u.SpeedLimitUpMbps, &u.SpeedLimitDownMbps, &u.AllowedProtocols, &expStr,
			&u.Note, &u.DeviceLimit, &u.FallbackAction, &u.FallbackSpeedLimit)
		if err == nil {
			u.IsActive = activeInt == 1
			users = append(users, u)
		}
	}
	c.JSON(http.StatusOK, users)
}

func handleCreateUser(c *gin.Context) {
	var req struct {
		Name               string   `json:"name" binding:"required"`
		TrafficLimitGB     *float64 `json:"traffic_limit_gb"`
		DurationDays       *int     `json:"duration_days"`
		AllowedProtocols   string   `json:"allowed_protocols"`
		Note               string   `json:"note"`
		DeviceLimit        int      `json:"device_limit"`
		FallbackAction     string   `json:"fallback_action"`
		FallbackSpeedLimit int      `json:"fallback_speed_limit"`
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

	_, err := database.DB.Exec(`INSERT INTO users (name, vless_uuid, hysteria2_password, traffic_limit_gb, expires_at, allowed_protocols, note, device_limit, fallback_action, fallback_speed_limit) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)` , req.Name, uuidStr, pass, limitGB, expiresAt, req.AllowedProtocols, req.Note, req.DeviceLimit, req.FallbackAction, req.FallbackSpeedLimit)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Пользователь с таким именем уже существует"})
		return
	}

	SyncAllNodes()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "name": req.Name, "vless_uuid": uuidStr, "hysteria_password": pass})
}

func handleUpdateUser(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name               string  `json:"name" binding:"required"`
		TrafficLimitGB     float64 `json:"traffic_limit_gb"`
		AllowedProtocols   string  `json:"allowed_protocols"`
		Note               string  `json:"note"`
		DeviceLimit        int     `json:"device_limit"`
		FallbackAction     string  `json:"fallback_action"`
		FallbackSpeedLimit int     `json:"fallback_speed_limit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := database.DB.Exec(`UPDATE users SET 
		name = ?, traffic_limit_gb = ?, allowed_protocols = ?, note = ?, device_limit = ?, fallback_action = ?, fallback_speed_limit = ? 
		WHERE id = ?`,
		req.Name, req.TrafficLimitGB, req.AllowedProtocols, req.Note, req.DeviceLimit, req.FallbackAction, req.FallbackSpeedLimit, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления"})
		return
	}

	SyncAllNodes()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleDeleteUser(c *gin.Context) {
	id := c.Param("id")
	_, err := database.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить пользователя"})
		return
	}

	SyncAllNodes()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleToggleUser(c *gin.Context) {
	id := c.Param("id")
	_, err := database.DB.Exec("UPDATE users SET is_active = 1 - is_active WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка переключения активности"})
		return
	}

	SyncAllNodes()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleBulkToggleRoute(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for _, id := range req.IDs {
		_, _ = database.DB.Exec("UPDATE users SET is_active = 1 - is_active WHERE id = ?", id)
	}
	SyncAllNodes()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleBulkDeleteRoute(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for _, id := range req.IDs {
		_, _ = database.DB.Exec("DELETE FROM users WHERE id = ?", id)
	}
	SyncAllNodes()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleBulkResetRoute(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for _, id := range req.IDs {
		_, _ = database.DB.Exec("UPDATE users SET traffic_used_bytes = 0, traffic_uplink_bytes = 0, traffic_downlink_bytes = 0 WHERE id = ?", id)
	}
	SyncAllNodes()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleGetNodes(c *gin.Context) {
	rows, err := database.DB.Query(`SELECT id, ip, name, location_code, location_name, 
		vless_port, vless_grpc_port, hysteria_port, tuic_port, naive_port, wireguard_port, shadowsocks_port, fallback_action, fallback_speed_limit, custom_dns, token, settings_json 
		FROM nodes`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type ExtendedNodeInfo struct {
		ID                 int64   `json:"id"`
		IP                 string  `json:"ip"`
		Name               string  `json:"name"`
		LocationCode       string  `json:"location_code"`
		LocationName       string  `json:"location_name"`
		VlessPort          int     `json:"vless_port"`
		VlessGrpcPort      int     `json:"vless_grpc_port"`
		HysteriaPort       int     `json:"hysteria_port"`
		TuicPort           int     `json:"tuic_port"`
		NaivePort          int     `json:"naive_port"`
		WireguardPort      int     `json:"wireguard_port"`
		ShadowsocksPort    int     `json:"shadowsocks_port"`
		FallbackAction     string  `json:"fallback_action"`
		FallbackSpeedLimit int     `json:"fallback_speed_limit"`
		CustomDNS          string  `json:"custom_dns"`
		Token              string  `json:"token"`
		SettingsJSON       string  `json:"settings_json"`
		CPUUsage           float64 `json:"cpu_usage"`
		RAMTotalBytes      float64 `json:"ram_total_bytes"`
		RAMUsedBytes       float64 `json:"ram_used_bytes"`
		RAMPercent         float64 `json:"ram_percent"`
		UptimeSeconds      float64 `json:"uptime_seconds"`
		Status             string  `json:"status"`
	}

	activeNodesMutex.RLock()
	defer activeNodesMutex.RUnlock()

	var result []ExtendedNodeInfo
	now := time.Now()

	for rows.Next() {
		var n ExtendedNodeInfo
		_ = rows.Scan(&n.ID, &n.IP, &n.Name, &n.LocationCode, &n.LocationName,
			&n.VlessPort, &n.VlessGrpcPort, &n.HysteriaPort, &n.TuicPort, &n.NaivePort, &n.WireguardPort, &n.ShadowsocksPort,
			&n.FallbackAction, &n.FallbackSpeedLimit, &n.CustomDNS, &n.Token, &n.SettingsJSON)

		n.Status = "offline"
		nodeKey := fmt.Sprintf("%d", n.ID)
		if telemetryNode, exists := activeNodes[nodeKey]; exists {
			if now.Sub(telemetryNode.LastSeen) <= 30*time.Second {
				n.Status = "online"
				n.CPUUsage = telemetryNode.CPUUsage
				n.RAMTotalBytes = telemetryNode.RAMTotalBytes
				n.RAMUsedBytes = telemetryNode.RAMUsedBytes
				n.RAMPercent = telemetryNode.RAMPercent
				n.UptimeSeconds = telemetryNode.UptimeSeconds
			}
		}
		result = append(result, n)
	}
	c.JSON(http.StatusOK, result)
}

func handleCreateNode(c *gin.Context) {
	var req struct {
		IP                 string `json:"ip" binding:"required"`
		Name               string `json:"name" binding:"required"`
		LocationCode       string `json:"location_code"`
		LocationName       string `json:"location_name"`
		VlessPort          int    `json:"vless_port"`
		VlessGrpcPort      int    `json:"vless_grpc_port"`
		HysteriaPort       int    `json:"hysteria_port"`
		TuicPort           int    `json:"tuic_port"`
		NaivePort          int    `json:"naive_port"`
		WireguardPort      int    `json:"wireguard_port"`
		ShadowsocksPort    int    `json:"shadowsocks_port"`
		FallbackAction     string `json:"fallback_action"`
		FallbackSpeedLimit int    `json:"fallback_speed_limit"`
		CustomDNS          string `json:"custom_dns"`
		Token              string `json:"token"`
		SettingsJSON       string `json:"settings_json"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.LocationCode == "" { req.LocationCode = "NL" }
	if req.LocationName == "" { req.LocationName = "Netherlands" }
	if req.VlessPort == 0 { req.VlessPort = 8443 }
	if req.VlessGrpcPort == 0 { req.VlessGrpcPort = 8447 }
	if req.HysteriaPort == 0 { req.HysteriaPort = 8444 }
	if req.TuicPort == 0 { req.TuicPort = 8445 }
	if req.NaivePort == 0 { req.NaivePort = 8446 }
	if req.WireguardPort == 0 { req.WireguardPort = 51820 }
	if req.ShadowsocksPort == 0 { req.ShadowsocksPort = 8448 }
	if req.FallbackAction == "" { req.FallbackAction = "throttle" }
	if req.FallbackSpeedLimit == 0 { req.FallbackSpeedLimit = 1 }
	if req.CustomDNS == "" { req.CustomDNS = "8.8.8.8,1.1.1.1" }
	if req.Token == "" { req.Token = utils.GenerateUUID() }
	if req.SettingsJSON == "" { req.SettingsJSON = "{}" }

	_, err := database.DB.Exec(`INSERT INTO nodes 
		(ip, name, location_code, location_name, vless_port, vless_grpc_port, hysteria_port, tuic_port, naive_port, wireguard_port, shadowsocks_port, fallback_action, fallback_speed_limit, custom_dns, token, settings_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.IP, req.Name, req.LocationCode, req.LocationName,
		req.VlessPort, req.VlessGrpcPort, req.HysteriaPort, req.TuicPort, req.NaivePort, req.WireguardPort, req.ShadowsocksPort,
		req.FallbackAction, req.FallbackSpeedLimit, req.CustomDNS, req.Token, req.SettingsJSON)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Узел с таким IP уже существует"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleUpdateNode(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		IP                 string `json:"ip" binding:"required"`
		Name               string `json:"name" binding:"required"`
		LocationCode       string `json:"location_code"`
		LocationName       string `json:"location_name"`
		VlessPort          int    `json:"vless_port"`
		VlessGrpcPort      int    `json:"vless_grpc_port"`
		HysteriaPort       int    `json:"hysteria_port"`
		TuicPort           int    `json:"tuic_port"`
		NaivePort          int    `json:"naive_port"`
		WireguardPort      int    `json:"wireguard_port"`
		ShadowsocksPort    int    `json:"shadowsocks_port"`
		FallbackAction     string `json:"fallback_action"`
		FallbackSpeedLimit int    `json:"fallback_speed_limit"`
		CustomDNS          string `json:"custom_dns"`
		Token              string `json:"token"`
		SettingsJSON       string `json:"settings_json"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := database.DB.Exec(`UPDATE nodes SET 
		ip = ?, name = ?, location_code = ?, location_name = ?, 
		vless_port = ?, vless_grpc_port = ?, hysteria_port = ?, tuic_port = ?, naive_port = ?, wireguard_port = ?, shadowsocks_port = ?,
		fallback_action = ?, fallback_speed_limit = ?, custom_dns = ?, token = ?, settings_json = ?
		WHERE id = ?`,
		req.IP, req.Name, req.LocationCode, req.LocationName,
		req.VlessPort, req.VlessGrpcPort, req.HysteriaPort, req.TuicPort, req.NaivePort, req.WireguardPort, req.ShadowsocksPort,
		req.FallbackAction, req.FallbackSpeedLimit, req.CustomDNS, req.Token, req.SettingsJSON, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления узла"})
		return
	}

	SyncNode(id)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleDeleteNode(c *gin.Context) {
	id := c.Param("id")
	_, err := database.DB.Exec("DELETE FROM nodes WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить узел"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func handleGetNodeStatus(c *gin.Context) {
	nodeID := c.Query("node_id")
	if nodeID == "" {
		nodeID = "1"
	}

	activeNodesMutex.RLock()
	node, exists := activeNodes[nodeID]
	activeNodesMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusOK, gin.H{"status": "offline"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":          node.Status,
		"cpu_usage":       node.CPUUsage,
		"ram_total_bytes": node.RAMTotalBytes,
		"ram_used_bytes":  node.RAMUsedBytes,
		"ram_percent":     node.RAMPercent,
		"uptime_seconds":  node.UptimeSeconds,
		"sing_box":        "online",
	})
}

func handleGetSettings(c *gin.Context) {
	rows, _ := database.DB.Query("SELECT key, value FROM settings")
	defer rows.Close()
	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		_ = rows.Scan(&k, &v)
		settings[k] = v
	}
	c.JSON(http.StatusOK, settings)
}

func handleSaveSettings(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err == nil {
		for k, v := range req {
			_, _ = database.DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", k, v)
		}
		SyncAllNodes()
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func handleGetLogs(c *gin.Context) {
	level := c.Query("level")
	comp := c.Query("component")
	search := c.Query("search")

	query := "SELECT level, component, message, created_at FROM system_logs WHERE 1=1"
	var args []interface{}

	if level != "" {
		query += " AND level = ?"
		args = append(args, strings.ToUpper(level))
	}
	if comp != "" {
		query += " AND component = ?"
		args = append(args, comp)
	}
	if search != "" {
		query += " AND message LIKE ?"
		args = append(args, "%"+search+"%")
	}
	query += " ORDER BY id DESC LIMIT 100"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type LogRow struct {
		Time      string `json:"time"`
		Level     string `json:"level"`
		Component string `json:"component"`
		Message   string `json:"message"`
	}

	var logs []LogRow
	for rows.Next() {
		var r LogRow
		if err := rows.Scan(&r.Level, &r.Component, &r.Message, &r.Time); err == nil {
			logs = append(logs, r)
		}
	}

	c.JSON(http.StatusOK, logs)
}

func handleStreamLogs(c *gin.Context) {
	nodeID := c.Query("node_id")
	if nodeID != "" && nodeID != "master" {
		NodeConnMutex.RLock()
		nc, exists := NodeConnections[nodeID]
		NodeConnMutex.RUnlock()

		if !exists {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Node is offline"})
			return
		}

		_ = nc.WriteJSON("start_logs", nil)

		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")

		for {
			select {
			case <-c.Request.Context().Done():
				_ = nc.WriteJSON("stop_logs", nil)
				return
			case logLine := <-nc.LogChan:
				_, _ = fmt.Fprintf(c.Writer, "data: %s\n\n", string(logLine))
				c.Writer.Flush()
			}
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
}

func handleNodeWebSocket(c *gin.Context) {
	token := c.GetHeader("X-Node-Token")
	if token == "" {
		token = c.Query("token")
	}

	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing node token"})
		return
	}

	var nodeID int64
	var nodeIP string
	var nodeName string
	err := database.DB.QueryRow("SELECT id, ip, name FROM nodes WHERE token = ?", token).Scan(&nodeID, &nodeIP, &nodeName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid node token"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[Master WS] Upgrade failed for %s: %v", nodeName, err)
		return
	}

	nodeKey := fmt.Sprintf("%d", nodeID)

	nc := &NodeConn{
		NodeID:  nodeKey,
		Conn:    conn,
		LogChan: make(chan []byte, 100),
	}

	NodeConnMutex.Lock()
	if old, exists := NodeConnections[nodeKey]; exists {
		_ = old.Conn.Close()
	}
	NodeConnections[nodeKey] = nc
	NodeConnMutex.Unlock()

	log.Printf("[Master WS] Node connected: %s (%s)", nodeName, nodeIP)

	go func() {
		syncPayload, err := getSyncDataForNode(nodeKey, nodeIP)
		if err == nil {
			_ = nc.WriteJSON("sync", syncPayload)
		}
	}()

	defer func() {
		_ = conn.Close()
		NodeConnMutex.Lock()
		delete(NodeConnections, nodeKey)
		NodeConnMutex.Unlock()
		log.Printf("[Master WS] Node disconnected: %s (%s)", nodeName, nodeIP)
	}()

	for {
		var msg WSMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			break
		}

		switch msg.Type {
		case "sysstats":
			var sysStats SysStatsPayload
			if err := json.Unmarshal(msg.Payload, &sysStats); err == nil {
				activeNodesMutex.Lock()
				activeNodes[nodeKey] = &NodeInfo{
					ID:                nodeKey,
					Name:              nodeName,
					IP:                nodeIP,
					LastSeen:          time.Now(),
					CPUUsage:          sysStats.CPUUsage,
					RAMTotalBytes:     sysStats.RAMTotalBytes,
					RAMUsedBytes:      sysStats.RAMUsedBytes,
					RAMPercent:        sysStats.RAMPercent,
					UptimeSeconds:     sysStats.UptimeSeconds,
					Status:            "online",
					ActiveConnections: sysStats.ActiveConnections,
				}
				activeNodesMutex.Unlock()
			}
		case "stats":
			var stats []NodeStat
			if err := json.Unmarshal(msg.Payload, &stats); err == nil {
				for _, stat := range stats {
					var query string
					if stat.Direction == "downlink" {
						query = "UPDATE users SET traffic_used_bytes = traffic_used_bytes + ?, traffic_downlink_bytes = traffic_downlink_bytes + ? WHERE name = ?"
					} else {
						query = "UPDATE users SET traffic_used_bytes = traffic_used_bytes + ?, traffic_uplink_bytes = traffic_uplink_bytes + ? WHERE name = ?"
					}
					_, _ = database.DB.Exec(query, stat.Bytes, stat.Bytes, stat.Username)
				}
			}
		case "log_line":
			select {
			case nc.LogChan <- msg.Payload:
			default:
			}
		}
	}
}

type AdminPayload struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	RoleID    int64  `json:"role_id"`
	RoleName  string `json:"role_name"`
	IsRoot    bool   `json:"is_root"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}