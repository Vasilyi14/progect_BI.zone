package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3" // драйвер SQLite
)

type SiteInfo struct {
	URL             string            `json:"url"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	StatusCode      int               `json:"status_code"`
	Server          string            `json:"server"`
	SecurityHeaders map[string]string `json:"security_headers"`
	Vulnerabilities []string          `json:"vulnerabilities"`
	Recommendations []string          `json:"recommendations"`
}

func main() {
	// Читаем данные от первой программы
	data, err := os.ReadFile("last_analysis.json")
	if err != nil {
		fmt.Println("Файл last_analysis.json не найден. Сначала запусти анализ сайта.")
		return
	}

	var info SiteInfo
	json.Unmarshal(data, &info)

	// Подключаемся к базе
	db, err := sql.Open("sqlite3", "sites_analysis.db")
	if err != nil {
		fmt.Println("Ошибка подключения к БД:", err)
		return
	}
	defer db.Close()

	// Создаём таблицу, если её нет
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sites (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT,
			title TEXT,
			description TEXT,
			status_code INTEGER,
			server TEXT,
			vulnerabilities TEXT,
			recommendations TEXT,
			scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		fmt.Println("Ошибка создания таблицы:", err)
		return
	}

	// Сохраняем в базу
	_, err = db.Exec(`
		INSERT INTO sites (url, title, description, status_code, server, vulnerabilities, recommendations)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		info.URL,
		info.Title,
		info.Description,
		info.StatusCode,
		info.Server,
		strings.Join(info.Vulnerabilities, "; "),
		strings.Join(info.Recommendations, "; "),
	)

	if err != nil {
		fmt.Println("Ошибка записи в БД:", err)
	} else {
		fmt.Println("✅ Данные успешно сохранены в базу данных sites_analysis.db")
	}
}
