package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
	"vpn-master/database"
)

type LogEntry struct {
	Time      time.Time              `json:"time"`
	Level     string                 `json:"level"`
	Component string                 `json:"component"`
	Message   string                 `json:"message"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

var (
	logFileMu sync.Mutex
	ipv4Regex = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b`)
)

func maskIPs(input string) string {
	return ipv4Regex.ReplaceAllString(input, "${1}xxx")
}
func rotateLogFile(filePath string, maxSize int64) {
	info, err := os.Stat(filePath)
	if err != nil {
		return // Файла нет или недоступен
	}

	if info.Size() < maxSize {
		return // Ротация не требуется
	}
	for i := 4; i >= 1; i-- {
		oldFile := fmt.Sprintf("%s.%d", filePath, i)
		newFile := fmt.Sprintf("%s.%d", filePath, i+1)
		_ = os.Rename(oldFile, newFile)
	}
	_ = os.Rename(filePath, filePath+".1")
}

func logEvent(level, component, msg string) {
	if database.GetSetting("log_mask_ips", "1") == "1" {
		msg = maskIPs(msg)
	}

	entry := LogEntry{
		Time:      time.Now(),
		Level:     level,
		Component: component,
		Message:   msg,
	}

	jsonBytes, err := json.Marshal(entry)
	if err == nil {
		logFileMu.Lock()
		dir := "logs"
		_ = os.MkdirAll(dir, 0755)
		filePath := filepath.Join(dir, "master.log")
		rotateLogFile(filePath, 10*1024*1024)

		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			_, _ = f.Write(append(jsonBytes, '\n'))
			f.Close()
		}
		logFileMu.Unlock()
	}

	if component == "system" || component == "database" {
		_, _ = database.DB.Exec("INSERT INTO system_logs (level, component, message, created_at) VALUES (?, ?, ?, ?)",
			entry.Level, entry.Component, entry.Message, entry.Time.Format("2006-01-02 15:04:05"))
	}
}

func Info(comp, msg string)  { logEvent("INFO", comp, msg) }
func Warn(comp, msg string)  { logEvent("WARN", comp, msg) }
func Error(comp, msg string) { logEvent("ERROR", comp, msg) }