package database

import (
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(filepath string) error {
	var err error
	DB, err = sql.Open("sqlite", filepath)
	if err != nil {
		return fmt.Errorf("ошибка подключения к SQLite: %v", err)
	}

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
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = DB.Exec(userTableQuery)
	if err != nil {
		return err
	}

	settingsTableQuery := `
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`

	_, err = DB.Exec(settingsTableQuery)
	if err != nil {
		return err
	}

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
	INSERT OR IGNORE INTO settings (key, value) VALUES ('vless_port', '8443');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('vless_grpc_port', '8447');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('hysteria_port', '8444');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('tuic_port', '8445');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('port_hopping_range', '20000-20050');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('hysteria_obfs', 'ObfsSecretPass123');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('naive_port', '8446');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('log_mask_ips', '1');
	INSERT OR IGNORE INTO settings (key, value) VALUES ('log_retention_days', '7');`

	_, _ = DB.Exec(insertDefaults)

	ensureRealityKeys()
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
			log.Fatalf("X25519 gen failed: %v", err)
		}
		pub := priv.PublicKey()

		privBase64 := base64.StdEncoding.EncodeToString(priv.Bytes())
		pubBase64 := base64.StdEncoding.EncodeToString(pub.Bytes())

		shortIDBytes := make([]byte, 8)
		_, _ = rand.Read(shortIDBytes)
		shortID := hex.EncodeToString(shortIDBytes)

		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_private_key', ?)", privBase64)
		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_public_key', ?)", pubBase64)
		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('reality_short_id', ?)", shortID)
	}
}