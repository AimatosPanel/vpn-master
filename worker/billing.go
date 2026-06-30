package worker

import (
	"log"
	"time"
	"vpn-master/database"
)

func StartBillingWorker() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
				query := `
		UPDATE users SET is_active = 0 
		WHERE is_active = 1 
		AND (
			(expires_at < datetime('now', 'localtime')) 
			OR 
			(traffic_limit_gb > 0 AND traffic_used_bytes >= (traffic_limit_gb * 1073741824))
		);`

		res, err := database.DB.Exec(query)
		if err != nil {
			log.Printf("[Master Billing] Ошибка проверки лимитов: %v", err)
			continue
		}
		affected, _ := res.RowsAffected()
		if affected > 0 {
			log.Printf("[Master Billing] Автоматически отключено пользователей: %d", affected)
		}
	}
}

func StartTrafficResetWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		now := time.Now()
		currentDay := now.Day()
		currentMonth := int(now.Month())

		rows, err := database.DB.Query("SELECT id FROM users WHERE traffic_reset_day = ? AND last_reset_month != ?", currentDay, currentMonth)
		if err != nil {
			continue
		}

		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()

		if len(ids) > 0 {
			for _, id := range ids {
				_, _ = database.DB.Exec("UPDATE users SET traffic_used_bytes = 0, traffic_uplink_bytes = 0, traffic_downlink_bytes = 0, last_reset_month = ?, is_active = 1 WHERE id = ?", currentMonth, id)
			}
			log.Printf("[Master Billing] Сброшен ежемесячный трафик для %d пользователей", len(ids))
		}
	}
}