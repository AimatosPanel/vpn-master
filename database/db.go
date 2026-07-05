package database

import (
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"vpn-master/utils"
)

var DB *sql.DB

func InitDB(filepath string) error {
	var err error
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys=ON", filepath)
	DB, err = sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("ошибка подключения к SQLite: %v", err)
	}

	DB.SetMaxOpenConns(10)
	DB.SetMaxIdleConns(10)
	rolesTableQuery := `
	CREATE TABLE IF NOT EXISTS roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		permissions TEXT NOT NULL
	);`
	if _, err = DB.Exec(rolesTableQuery); err != nil {
		return err
	}
	adminsTableQuery := `
	CREATE TABLE IF NOT EXISTS admins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role_id INTEGER NOT NULL DEFAULT 0,
		is_root INTEGER NOT NULL DEFAULT 0,
		email TEXT UNIQUE,
		reset_token TEXT,
		reset_token_expires DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(role_id) REFERENCES roles(id)
	);`
	if _, err = DB.Exec(adminsTableQuery); err != nil {
		return err
	}

	_, _ = DB.Exec("ALTER TABLE admins ADD COLUMN role_id INTEGER NOT NULL DEFAULT 0")
	_, _ = DB.Exec("ALTER TABLE admins ADD COLUMN is_root INTEGER NOT NULL DEFAULT 0")
	userTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		is_active INTEGER NOT NULL DEFAULT 1,
		vless_uuid TEXT NOT NULL,
		hysteria2_password TEXT NOT NULL,
		traffic_limit_gb REAL DEFAULT 0,
		traffic_used_bytes INTEGER DEFAULT 0,
		traffic_uplink_bytes INTEGER DEFAULT 0,
		traffic_downlink_bytes INTEGER DEFAULT 0,
		speed_limit_up_mbps INTEGER DEFAULT 0,
		speed_limit_down_mbps INTEGER DEFAULT 0,
		allowed_protocols TEXT DEFAULT 'vless,hysteria2,tuic,naive',
		allowed_ips INTEGER DEFAULT 0,
		traffic_reset_day INTEGER DEFAULT 0,
		last_reset_month INTEGER DEFAULT 0,
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		device_limit INTEGER DEFAULT 0,
		fallback_action TEXT DEFAULT 'default',
		fallback_speed_limit INTEGER DEFAULT 0,
		note TEXT DEFAULT ''
	);`
	if _, err = DB.Exec(userTableQuery); err != nil {
		return err
	}
	settingsTableQuery := `
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`
	if _, err = DB.Exec(settingsTableQuery); err != nil {
		return err
	}
	var roleCount int
	err = DB.QueryRow("SELECT COUNT(*) FROM roles").Scan(&roleCount)
	if err == nil && roleCount == 0 {
		_, _ = DB.Exec("INSERT INTO roles (name, permissions) VALUES ('Root Role', 'clients:read,clients:write,nodes:read,nodes:write,settings:read,settings:write,logs:read,admins:manage')")
		_, _ = DB.Exec("INSERT INTO roles (name, permissions) VALUES ('Operator', 'clients:read,clients:write,nodes:read,nodes:write,settings:read,logs:read')")
		_, _ = DB.Exec("INSERT INTO roles (name, permissions) VALUES ('Support', 'clients:read,nodes:read,settings:read,logs:read')")
	}

	var rootRoleID int64
	_ = DB.QueryRow("SELECT id FROM roles WHERE name = 'Root Role'").Scan(&rootRoleID)

	if rootRoleID > 0 {
		_, _ = DB.Exec("UPDATE admins SET role_id = ?, is_root = 1 WHERE username = 'admin' OR id = 1", rootRoleID)
	}
	var adminCount int
	err = DB.QueryRow("SELECT COUNT(*) FROM admins").Scan(&adminCount)
	if err == nil && adminCount == 0 && rootRoleID > 0 {
		defaultPassword := "adminpassword"
		hashed, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), 12)
		if err == nil {
			_, err = DB.Exec("INSERT INTO admins (username, password_hash, role_id, is_root, email) VALUES (?, ?, ?, ?, ?)",
				"admin", string(hashed), rootRoleID, 1, "admin@aimatos.internal")
			if err == nil {
				nowStr := time.Now().Format(time.RFC3339)
				_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_at', ?)", nowStr)
				_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('plain_creds_admin', 'admin:adminpassword')")
			}
		}
	}
	userDevicesTableQuery := `
	CREATE TABLE IF NOT EXISTS user_devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		hwid TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`
	_, _ = DB.Exec(userDevicesTableQuery)
	_, _ = DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_hwid ON user_devices(user_id, hwid);")
	nodesTableQuery := `
	CREATE TABLE IF NOT EXISTS nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL,
		location_code TEXT NOT NULL DEFAULT 'NL',
		location_name TEXT NOT NULL DEFAULT 'Netherlands',
		vless_port INTEGER DEFAULT 8443,
		vless_grpc_port INTEGER DEFAULT 8447,
		hysteria_port INTEGER DEFAULT 8444,
		tuic_port INTEGER DEFAULT 8445,
		naive_port INTEGER DEFAULT 8446,
		wireguard_port INTEGER DEFAULT 51820,
		shadowsocks_port INTEGER DEFAULT 8448,
		fallback_action TEXT DEFAULT 'throttle',
		fallback_speed_limit INTEGER DEFAULT 1,
		custom_dns TEXT DEFAULT '8.8.8.8,1.1.1.1',
		token TEXT DEFAULT '',
		settings_json TEXT DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, _ = DB.Exec(nodesTableQuery)

	_, _ = DB.Exec("ALTER TABLE nodes ADD COLUMN wireguard_port INTEGER DEFAULT 51820")
	_, _ = DB.Exec("ALTER TABLE nodes ADD COLUMN shadowsocks_port INTEGER DEFAULT 8448")
	_, _ = DB.Exec("ALTER TABLE nodes ADD COLUMN settings_json TEXT DEFAULT '{}'")
	historyTableQuery := `
	CREATE TABLE IF NOT EXISTS traffic_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		username TEXT NOT NULL,
		bytes_up INTEGER NOT NULL,
		bytes_down INTEGER NOT NULL,
		recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, _ = DB.Exec(historyTableQuery)
	systemLogsQuery := `
	CREATE TABLE IF NOT EXISTS system_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		level TEXT NOT NULL,
		component TEXT NOT NULL,
		message TEXT NOT NULL,
		context TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, _ = DB.Exec(systemLogsQuery)
	insertDefaults := `
	INSERT OR IGNORE INTO settings (key, value) VALUES ('server_ip', '127.0.0.1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('reality_sni', 'microsoft.com');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('api_key', 'SuperSecretAdminKey123');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_hopping_range', '20000-20050');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('hysteria_obfs', 'ObfsSecretPass123');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('log_mask_ips', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('log_retention_days', '7');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('brand_name', 'AimatosPanel');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('server_location', '🇳🇱 Amsterdam, Netherlands');
	
	INSERT OR IGNORE INTO settings (key, value) VALUES ('torrent_policy', 'block');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('torrent_throttle_speed', '512');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('dns_adblock', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('dns_malware', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('dns_adblock_custom_urls', '');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('dns_upstream_servers', '1.1.1.1,8.8.8.8');

	INSERT OR IGNORE INTO settings (key, value) VALUES ('wireguard_subnet', '10.8.0.0/24');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('wireguard_mtu', '1420');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('wireguard_dns', '1.1.1.1, 10.8.0.1');
	
	INSERT OR IGNORE INTO settings (key, value) VALUES ('shadowsocks_method', '2022-blake3-aes-128-gcm');

	-- Глобальные переключатели активности протоколов
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vless_tcp_reality', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vless_grpc_reality', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vless_h2_reality', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vless_quic_reality', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vless_httpupgrade_reality', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vless_ws_reality', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vless_xtls_vision', '1');

	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vmess_ws_tls', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vmess_grpc', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vmess_httpupgrade', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_vmess_reality', '1');

	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_trojan_reality', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_trojan_grpc', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_trojan_ws_tls', '1');

	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_wireguard', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_shadowsocks', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_socks5_tls', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_http_tls', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('enable_naive', '1');

	-- Настройки портов по умолчанию
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vless_h2_reality', '8450');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vless_quic_reality', '8451');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vless_httpupgrade_reality', '8452');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vless_ws_reality', '8453');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vless_xtls_vision', '8454');

	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vmess_ws_tls', '8455');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vmess_grpc', '8456');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vmess_httpupgrade', '8457');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_vmess_reality', '8458');

	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_trojan_reality', '8459');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_trojan_grpc', '8460');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_trojan_ws_tls', '8461');

	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_socks5_tls', '8462');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_http_tls', '8463');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_naive', '8446');

	-- SSL сертификаты домена
	INSERT OR IGNORE INTO settings (key, value) VALUES ('tls_cert', '');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('tls_key', '');`
	_, _ = DB.Exec(insertDefaults)

	ensureRealityKeys()
	ensureWireGuardKeys()
	var privVal, pubVal string
	_ = DB.QueryRow("SELECT value FROM settings WHERE key = 'reality_private_key'").Scan(&privVal)
	_ = DB.QueryRow("SELECT value FROM settings WHERE key = 'reality_public_key'").Scan(&pubVal)
	if strings.ContainsAny(privVal, "+/=") || strings.ContainsAny(pubVal, "+/=") || privVal == "" || pubVal == "" {
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(rand.Reader)
		if err == nil {
			pub := priv.PublicKey()
			privBase64 := base64.RawURLEncoding.EncodeToString(priv.Bytes())
			pubBase64 := base64.RawURLEncoding.EncodeToString(pub.Bytes())

			shortIDBytes := make([]byte, 8)
			_, _ = rand.Read(shortIDBytes)
			shortID := hex.EncodeToString(shortIDBytes)

			_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_private_key', ?)", privBase64)
			_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_public_key', ?)", pubBase64)
			_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_short_id', ?)", shortID)
			log.Println("[Database] Ключи REALITY успешно регенерированы/отремонтированы в формате URL-Safe Base64 (RawURLEncoding)")
		}
	}

	return nil
}

func GetSetting(key, fallback string) string {
	if DB == nil {
		return fallback
	}
	var value string
	err := DB.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err != nil {
		return fallback
	}
	return value
}

func ensureRealityKeys() {
	var privVal string
	err := DB.QueryRow("SELECT value FROM settings WHERE key = 'reality_private_key'").Scan(&privVal)
	if err != nil || privVal == "" {
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("X25519 generation failed: %v", err)
		}
		pub := priv.PublicKey()

		privBase64 := base64.RawURLEncoding.EncodeToString(priv.Bytes())
		pubBase64 := base64.RawURLEncoding.EncodeToString(pub.Bytes())

		shortIDBytes := make([]byte, 8)
		_, _ = rand.Read(shortIDBytes)
		shortID := hex.EncodeToString(shortIDBytes)

		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_private_key', ?)", privBase64)
		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_public_key', ?)", pubBase64)
		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_short_id', ?)", shortID)
	}
}

func ensureWireGuardKeys() {
	var privVal string
	err := DB.QueryRow("SELECT value FROM settings WHERE key = 'wireguard_private_key'").Scan(&privVal)
	if err != nil || privVal == "" {
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			log.Printf("[Database] Failed to generate Wireguard server keys: %v", err)
			return
		}
		pub := priv.PublicKey()

		privBase64 := base64.StdEncoding.EncodeToString(priv.Bytes())
		pubBase64 := base64.StdEncoding.EncodeToString(pub.Bytes())

		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('wireguard_private_key', ?)", privBase64)
		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('wireguard_public_key', ?)", pubBase64)
	}
}

func SetEncryptedSetting(key, plaintext string) error {
	encrypted, err := utils.EncryptValue(plaintext)
	if err != nil {
		return err
	}
	_, err = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", key, encrypted)
	return err
}

func GetDecryptedSetting(key, fallback string) string {
	var encrypted string
	err := DB.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&encrypted)
	if err != nil {
		return fallback
	}
	decrypted, err := utils.DecryptValue(encrypted)
	if err != nil {
		return fallback
	}
	return decrypted
}