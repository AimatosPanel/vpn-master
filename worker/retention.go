package worker

import (
	"time"
	"vpn-master/database"
)

func StartLogRetentionWorker() {
	ticker := time.NewTicker(12 * time.Hour)
	for range ticker.C {
		retentionDays := database.GetSetting("log_retention_days", "7")
		_, _ = database.DB.Exec("DELETE FROM system_logs WHERE created_at < datetime('now', '-' || ? || ' days', 'localtime')", retentionDays)
	}
}