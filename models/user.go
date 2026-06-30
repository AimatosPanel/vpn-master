package models

import "time"

type User struct {
	ID                   int64      `json:"id"`
	Name                 string     `json:"name"`
	IsActive             bool       `json:"is_active"`
	VlessUUID            string     `json:"vless_uuid"`
	Hysteria2Password    string     `json:"hysteria2_password"`
	TrafficLimitGB       float64    `json:"traffic_limit_gb"`
	TrafficUsedBytes     int64      `json:"traffic_used_bytes"`
	TrafficUplinkBytes   int64      `json:"traffic_uplink_bytes"`
	TrafficDownlinkBytes int64      `json:"traffic_downlink_bytes"`
	SpeedLimitUpMbps     int        `json:"speed_limit_up_mbps"`
	SpeedLimitDownMbps   int        `json:"speed_limit_down_mbps"`
	AllowedProtocols     string     `json:"allowed_protocols"`
	AllowedIPs           int        `json:"allowed_ips"`
	TrafficResetDay      int        `json:"traffic_reset_day"`
	ExpiresAt            *time.Time `json:"expires_at"`
	CreatedAt            time.Time  `json:"created_at"`
	DownloadSpeed        int64      `json:"download_speed"`
	UploadSpeed          int64      `json:"upload_speed"`
}