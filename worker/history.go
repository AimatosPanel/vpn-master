package worker

import (
	"sync"
	"time"
	"vpn-master/database"
)

var (
	lastRecordedUp   = make(map[int64]int64)
	lastRecordedDown = make(map[int64]int64)
	lastRecordedMu   sync.Mutex
)

func StartTrafficHistoryLogger() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		logTrafficDelta()
	}
}

func logTrafficDelta() {
	rows, err := database.DB.Query("SELECT id, name, traffic_uplink_bytes, traffic_downlink_bytes FROM users")
	if err != nil {
		return
	}
	defer rows.Close()

	lastRecordedMu.Lock()
	defer lastRecordedMu.Unlock()

	for rows.Next() {
		var id int64
		var name string
		var up, down int64
		if err := rows.Scan(&id, &name, &up, &down); err == nil {
			lastUp, okUp := lastRecordedUp[id]
			lastDown, okDown := lastRecordedDown[id]

			if !okUp || !okDown {
				lastRecordedUp[id] = up
				lastRecordedDown[id] = down
				continue
			}

			deltaUp := up - lastUp
			deltaDown := down - lastDown

			if deltaUp > 0 || deltaDown > 0 {
				_, err = database.DB.Exec("INSERT INTO traffic_history (user_id, username, bytes_up, bytes_down) VALUES (?, ?, ?, ?)", id, name, deltaUp, deltaDown)
				if err == nil {
					lastRecordedUp[id] = up
					lastRecordedDown[id] = down
				}
			}
		}
	}
}