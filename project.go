import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Request struct {
	URL string `json:"url"`
}

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

var lastResult SiteInfo

func main() {
	http.HandleFunc("/get-info", getInfoHandler)
	http.HandleFunc("/result", showResultPage)

	fmt.Println("🚀 Сервер запущен на http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func getInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "bad json"})
		return
	}

	url := req.URL
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	info, err := analyzeSite(url)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	lastResult = info

	// Сохраняем данные для второй программы (в JSON)
	saveToJSON(info)

	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"redirect": "/result",
	})
}

// ==================== МОДУЛЬ АНАЛИЗА САЙТА ====================
func analyzeSite(url string) (SiteInfo, error) {
	client := &http.Client{
		Timeout: 12 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return SiteInfo{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	info := SiteInfo{
		URL:             url,
		Title:           extractTitle(html),
		Description:     extractDescription(html),
		StatusCode:      resp.StatusCode,
		Server:          resp.Header.Get("Server"),
		SecurityHeaders: make(map[string]string),
		Vulnerabilities: []string{},
		Recommendations: []string{},
	}

	// Проверка security headers
	headers := []string{"Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection",
		"Content-Security-Policy", "X-Content-Type-Options"}
	for _, h := range headers {
		if val := resp.Header.Get(h); val != "" {
			info.SecurityHeaders[h] = val
		}
	}

	// Базовый анализ уязвимостей
	if !strings.HasPrefix(url, "https://") {
		info.Vulnerabilities = append(info.Vulnerabilities, "Сайт использует незащищённый HTTP протокол")
		info.Recommendations = append(info.Recommendations, "Перейти на HTTPS")
	}

	if resp.Header.Get("X-Frame-Options") == "" && resp.Header.Get("Content-Security-Policy") == "" {
		info.Vulnerabilities = append(info.Vulnerabilities, "Отсутствует защита от Clickjacking")
	}

	if resp.Header.Get("X-XSS-Protection") == "" && resp.Header.Get("Content-Security-Policy") == "" {
		info.Vulnerabilities = append(info.Vulnerabilities, "Слабая защита от XSS-атак")
	}

	if info.Server != "" {
		info.Recommendations = append(info.Recommendations, "Обнаружен сервер: "+info.Server)
	}

	return info, nil
}

func extractTitle(html string) string {
	if idx := strings.Index(html, "<title>"); idx != -1 {
		if end := strings.Index(html[idx:], "</title>"); end != -1 {
			return strings.TrimSpace(html[idx+7 : idx+end])
		}
	}
	return "Без заголовка"
}

func extractDescription(html string) string {
	if idx := strings.Index(html, `name="description"`); idx != -1 {
		if cIdx := strings.Index(html[idx:], `content="`); cIdx != -1 {
			start := idx + cIdx + 9
			if end := strings.Index(html[start:], `"`); end != -1 {
				return strings.TrimSpace(html[start : start+end])
			}
		}
	}
	return "Описание не найдено"
}

// Сохраняет результат в JSON (для второй программы)
func saveToJSON(info SiteInfo) {
	data, _ := json.MarshalIndent(info, "", "  ")
	os.WriteFile("last_analysis.json", data, 0644)
	fmt.Println("💾 Данные анализа сохранены в last_analysis.json")
}

// ==================== СТРАНИЦА РЕЗУЛЬТАТА ====================
func showResultPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	html := `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Результат анализа</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f6f9; }
        .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 5px 20px rgba(0,0,0,0.1); max-width: 1000px; margin: 0 auto; }
        .vuln { color: #d32f2f; }
        .good { color: #388e3c; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🔍 Результат анализа сайта</h1>
        <p><strong>Ссылка:</strong> ` + lastResult.URL + `</p>
        <p><strong>Заголовок:</strong> ` + lastResult.Title + `</p>
        <p><strong>Описание:</strong> ` + lastResult.Description + `</p>
        <p><strong>Статус:</strong> ` + fmt.Sprintf("%d", lastResult.StatusCode) + `</p>
        <p><strong>Сервер:</strong> ` + lastResult.Server + `</p>

        <h2>🔐 Security Headers</h2>
        <pre>` + fmt.Sprintf("%+v", lastResult.SecurityHeaders) + `</pre>

        <h2 class="vuln">⚠️ Обнаруженные проблемы</h2>
        <ul>`

	for _, v := range lastResult.Vulnerabilities {
		html += `<li class="vuln">` + v + `</li>`
	}
	if len(lastResult.Vulnerabilities) == 0 {
		html += `<li class="good">Критических уязвимостей не обнаружено</li>`
	}

	html += `</ul><h2>Рекомендации</h2><ul>`

	for _, rec := range lastResult.Recommendations {
		html += `<li>` + rec + `</li>`
	}

	html += `</ul>
        <hr>
        <a href="/" style="color:#667eea; font-size:18px;">← Проверить другой сайт</a>
    </div>
</body>
</html>`

	fmt.Fprint(w, html)
}
