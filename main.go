package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"vpn-master/database"
	"vpn-master/logger"
	"vpn-master/worker"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
)

type UserSpeed struct {
	DownloadSpeed int64 `json:"download_speed"`
	UploadSpeed   int64 `json:"upload_speed"`
}

type NodeStat struct {
	Username  string `json:"username"`
	Bytes     int64  `json:"bytes"`
	Direction string `json:"direction"`
}

type ActiveConnInfo struct {
	Username  string   `json:"username"`
	IPs       []string `json:"ips"`
	Protocols []string `json:"protocols"`
	SpeedDL   int64    `json:"speed_dl"`
	SpeedUL   int64    `json:"speed_ul"`
}

type SysStatsPayload struct {
	CPUUsage            float64          `json:"cpu_usage"`
	RAMTotalBytes       float64          `json:"ram_total_bytes"`
	RAMUsedBytes        float64          `json:"ram_used_bytes"`
	RAMPercent          float64          `json:"ram_percent"`
	UptimeSeconds       float64          `json:"uptime_seconds"`
	OnlineUsers         int              `json:"online_users"`
	TotalUsers          int              `json:"total_users"`
	GlobalDownloadSpeed int64            `json:"global_download_speed"`
	GlobalUploadSpeed   int64            `json:"global_upload_speed"`
	ActiveConnections   []ActiveConnInfo `json:"active_connections,omitempty"`
}

type NodeInfo struct {
	ID                string           `json:"id"`
	Name              string           `json:"name"`
	IP                string           `json:"ip"`
	LastSeen          time.Time        `json:"last_seen"`
	CPUUsage          float64          `json:"cpu_usage"`
	RAMTotalBytes     float64          `json:"ram_total_bytes"`
	RAMUsedBytes      float64          `json:"ram_used_bytes"`
	RAMPercent        float64          `json:"ram_percent"`
	UptimeSeconds     float64          `json:"uptime_seconds"`
	Status            string           `json:"status"`
	ActiveConnections []ActiveConnInfo `json:"active_connections,omitempty"`
}

type NodeConn struct {
	NodeID  string
	Conn    *websocket.Conn
	Mu      sync.Mutex
	LogChan chan []byte
}

var (
	userSpeeds      = make(map[string]*UserSpeed)
	userSpeedsMutex sync.RWMutex

	activeNodes      = make(map[string]*NodeInfo)
	activeNodesMutex sync.RWMutex

	NodeConnections = make(map[string]*NodeConn)
	NodeConnMutex   sync.RWMutex
)

func main() {
	setupGracefulShutdown()

	fmt.Println("==================================================")
	fmt.Println("🛰️  ЗАПУСК ЦЕНТРАЛЬНОГО API БЭКЕНДА (HEADLESS)")
	fmt.Println("==================================================")

	if err := database.InitDB("panel.db"); err != nil {
		log.Fatalf("Ошибка инициализации базы данных: %v", err)
	}
	logger.Info("system", "Мастер-база данных panel.db успешно инициализирована")

	go worker.StartBillingWorker()
	go worker.StartTrafficResetWorker()
	go worker.StartTrafficHistoryLogger()
	go worker.StartLogRetentionWorker()

	r := SetupRouter()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	enableAcme := database.GetSetting("enable_acme", "0")
	acmeDomain := database.GetSetting("acme_domain", "")

	if enableAcme == "1" && acmeDomain != "" {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acmeDomain),
			Cache:      autocert.DirCache("/var/aimatos/certs"),
		}
		go func() {
			log.Printf("[Master ACME] HTTP-сервер для ACME-вызовов запущен на порту 80")
			if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
				log.Printf("[Master ACME] Ошибка запуска ACME HTTP: %v", err)
			}
		}()
		go func() {
			log.Printf("[Master ACME] Secure HTTPS-сервер запущен для домена: %s (Порт 443)", acmeDomain)
			server := &http.Server{
				Addr:    ":443",
				Handler: r,
				TLSConfig: &tls.Config{
					GetCertificate: certManager.GetCertificate,
					MinVersion:     tls.VersionTLS12,
				},
			}
			if err := server.ListenAndServeTLS("", ""); err != nil {
				log.Printf("[Master ACME] Ошибка запуска HTTPS: %v", err)
			}
		}()
	}

	logger.Info("system", "Веб-сервер API запущен на порту "+port)
	_ = r.Run("0.0.0.0:" + port)
}

func setupGracefulShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Завершение работы бэкенда...")
		os.Exit(0)
	}()
}