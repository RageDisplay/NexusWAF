# 🛡️ NexusWAF - Web Application Firewall

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.24.1-blue.svg)](https://golang.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com)

Высокопроизводительная система защиты веб-приложений с интеллектуальным анализом угроз и веб-интерфейсом управления в реальном времени.

## 📋 Содержание

- [Обзор](#-обзор)
- [Быстрый старт](#-быстрый-старт)
- [Архитектура](#-архитектура)
- [Использование](#-использование)
- [API](#-api)
- [Разработка](#-разработка)
- [Troubleshooting](#-troubleshooting)

---

## 🎯 Обзор

**NexusWAF** - это микросервисная архитектура для защиты веб-приложений с поддержкой:

✅ **SQL Injection Protection** - обнаружение и блокировка SQL-атак  
✅ **XSS Protection** - защита от кросс-сайтовых скриптов  
✅ **Command Injection Protection** - блокировка инъекций команд оболочки  
✅ **Path Traversal Protection** - защита от обхода каталогов  
✅ **Rate Limiting** - защита от DDoS-атак  
✅ **Real-time Dashboard** - мониторинг в реальном времени  
✅ **Dynamic Port Configuration** - динамическая смена портов без перезагрузки  

---

## 🚀 Быстрый старт

### Требования

- **Docker** >= 20.10
- **Docker Compose** >= 1.29
- **Python 3.6+** (для демона смены портов)
- **2GB+ RAM**

### Установка и запуск

**1. Клонировать репозиторий**
```bash
git clone <repository-url>
cd Golang-Redis-Waf
```

**2. Запустить контейнеры**
```bash
docker-compose build
docker-compose up -d
```

**3. Запустить демон мониторинга портов (на хосте)**
```bash
# Установить зависимости
pip3 install redis

# Запустить демон
python3 waf-port-monitor.py &
```

**4. Открыть интерфейсы**

| Сервис | URL | Описание |
|--------|-----|---------|
| 🖥️ Admin Dashboard | http://localhost:8080 | Веб-интерфейс управления |
| 🔗 WAF Proxy | http://localhost:8081 | Точка входа для защищаемого приложения |
| 📊 Redis | localhost:6379 | Хранилище данных (внутреннее) |

---

## 🏗️ Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    Admin Dashboard                       │
│                    (waf-admin:8080)                      │
└────────────────────┬────────────────────────────────────┘
                     │ Config Updates
                     ▼
┌─────────────────────────────────────────────────────────┐
│                      Redis Cache                         │
│                   (redis:6379)                           │
│  ├─ Signatures (SQLi, XSS, CMDi, Path)                 │
│  ├─ Configuration                                        │
│  ├─ Statistics & Logs                                   │
│  └─ Port Change Signals                                 │
└────┬────────────────┬────────────────────────────────────┘
     │                │
     ▼                ▼
┌──────────────┐  ┌──────────────────┐
│  WAF Proxy   │  │ Signature DB     │
│  (8081)      │  │ (8082)           │
│              │  │                  │
│ ├─ Check SQL │  │ ├─ Load Patterns│
│ ├─ Check XSS │  │ ├─ Update Rules │
│ ├─ Check CMDi│  │ └─ Manage Data  │
│ └─ Log Data  │  └──────────────────┘
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌──────────────────┐
│   Analyzer   │     │ Your Protected   │
│   (8083)     │────▶│ Application      │
│              │     │                  │
│ ├─ Rate Limit│     │ (on your host)   │
│ ├─ Heuristics│     │ e.g. :7000       │
│ └─ Pattern   │     └──────────────────┘
│   Matching   │
└──────────────┘

┌─────────────────────────────────────────┐
│   Port Monitor Daemon (HOST)            │
│   (waf-port-monitor.py)                │
│   Watches: waf:port:requested in Redis │
│   Action: docker-compose restart       │
└─────────────────────────────────────────┘
```

### Микросервисы

#### 1. 🔐 **WAF Proxy** (`wafproxy/`)
Основной прокси-сервер с проверкой безопасности.

| Параметр | Значение |
|----------|----------|
| Порт | 8081 (по умолчанию, можно менять) |
| Язык | Go 1.24.1 |
| Роль | Обработка запросов, проверка сигнатур |

**Функции:**
- Реверс-прокси к целевому приложению
- Проверка запросов по сигнатурам атак
- Блокировка malicious-запросов
- Сбор статистики и логов
- Отслеживание конфигурации в Redis

#### 2. 📚 **Signature Database** (`signaturedb/`)
Управление сигнатурами и паттернами атак.

| Параметр | Значение |
|----------|----------|
| Порт | 8082 |
| Язык | Go 1.24.1 |
| Роль | Хранение и управление правилами |

**Функции:**
- Загрузка паттернов в Redis
- Поддержка 4 типов атак
- API для управления сигнатурами

#### 3. 🔍 **Request Analyzer** (`analyzer/`)
Глубокий анализ подозрительных запросов.

| Параметр | Значение |
|----------|----------|
| Порт | 8083 |
| Язык | Go 1.24.1 |
| Роль | Продвинутый анализ |

**Функции:**
- Rate limiting (защита от DDoS)
- Эвристический анализ
- Детекция сложных атак

#### 4. 🎛️ **Admin Dashboard** (`waf-admin/`)
Веб-интерфейс для управления и мониторинга.

| Параметр | Значение |
|----------|----------|
| Порт | 8080 |
| Язык | Go 1.24.1 |
| Роль | Управление и мониторинг |

**Функции:**
- Панель управления в реальном времени
- Изменение конфигурации (модули защиты, порт, целевой URL)
- Просмотр статистики и логов
- WebSocket для обновлений в реальном времени

#### 5. 💾 **Redis**
Централизованное хранилище данных.

| Параметр | Значение |
|----------|----------|
| Порт | 6379 |
| Образ | redis:alpine |
| Роль | Общее хранилище |

**Хранимые данные:**
- Сигнатуры атак (SQLi, XSS, CMDi, Path Traversal)
- Конфигурация системы
- Статистика запросов
- Логи безопасности
- Сигналы смены портов

---

## 📖 Использование

### Веб-интерфейс

#### Главная панель
**URL:** http://localhost:8080

Отображает:
- 📊 Общее количество запросов
- 🚫 Количество заблокированных запросов
- 📈 Процент блокировок
- 📉 График угроз по типам

#### Конфигурация
**URL:** http://localhost:8080/config

Можно менять:
- **Target URL** - адрес защищаемого приложения (например: http://192.168.200.50:7000)
- **Listen Port** - порт WAF (например: 8081, 9090, 3000)
- **Enable SQLi Protection** - вкл/выкл защиту от SQL-инъекций
- **Enable XSS Protection** - вкл/выкл защиту от XSS
- **Enable CMDi Protection** - вкл/выкл защиту от Command Injection
- **Enable Path Traversal Protection** - вкл/выкл защиту от Path Traversal

#### Статистика
**URL:** http://localhost:8080/stats

Детальная информация:
- Всего запросов
- Заблокировано запросов
- Угрозы по типам (SQLi, XSS, CMDi, Path Traversal)

#### Логи
**URL:** http://localhost:8080/logs

История всех событий:
- Timestamp
- IP источника
- Метод и URL
- Обнаруженные угрозы
- Действие (блокировка/пропуск)

### Примеры атак для тестирования

#### SQL Injection
```bash
curl "http://localhost:8081/?id=' OR '1'='1'--"
curl "http://localhost:8081/?id=1; DROP TABLE users--"
curl "http://localhost:8081/?id=1 UNION SELECT * FROM users"
```

#### XSS
```bash
curl "http://localhost:8081/?search=<script>alert('XSS')</script>"
curl "http://localhost:8081/?name=<img src=x onerror=alert(1)>"
```

#### Command Injection
```bash
curl "http://localhost:8081/?cmd=ls;whoami"
curl "http://localhost:8081/?file=data.txt|cat /etc/passwd"
```

#### Path Traversal
```bash
curl "http://localhost:8081/download?file=../../../etc/passwd"
curl "http://localhost:8081/files/..%2f..%2fetc%2fpasswd"
```

---

## 🔌 API

### Конфигурация

**GET** `/api/config` - получить текущую конфигурацию
```bash
curl http://localhost:8080/api/config
```

**POST** `/api/config` - обновить конфигурацию
```bash
curl -X POST http://localhost:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://app:7000",
    "listen_port": "9090",
    "enable_sqli": true,
    "enable_xss": true,
    "enable_cmdi": true,
    "enable_path": true
  }'
```

### Статистика

**GET** `/api/stats` - получить статистику
```bash
curl http://localhost:8080/api/stats
```

**Ответ:**
```json
{
  "total_requests": 1250,
  "blocked_requests": 42,
  "threats_by_type": {
    "sqli": 15,
    "xss": 12,
    "cmdi": 10,
    "pathtraversal": 5
  },
  "last_updated": "2024-01-01T12:00:00Z"
}
```

### Логи

**GET** `/api/logs?count=100` - получить последние 100 логов
```bash
curl "http://localhost:8080/api/logs?count=100"
```

### WebSocket

**WS** `/api/ws` - получать обновления в реальном времени
```javascript
const ws = new WebSocket('ws://localhost:8080/api/ws');
ws.onmessage = (event) => {
  const stats = JSON.parse(event.data);
  console.log(stats);
};
```

---

## 💻 Разработка

### Требования для разработки

- Go 1.24.1+
- Docker & Docker Compose
- Redis CLI (опционально)
- Python 3.6+ (для скриптов)

### Структура проекта

```
Golang-Redis-Waf/
├── docker-compose.yml          # Конфигурация контейнеров
├── wafproxy/                   # WAF Proxy сервис
│   ├── main.go                 # Основной прокси
│   ├── ratelimiter.go          # Rate limiting логика
│   ├── Dockerfile              # Docker образ
│   └── go.mod                  # Go зависимости
├── signaturedb/                # Signature Database сервис
│   ├── main.go                 # Загрузка сигнатур
│   ├── Dockerfile
│   └── go.mod
├── analyzer/                   # Request Analyzer сервис
│   ├── main.go                 # Анализ запросов
│   ├── ratelimiter.go          # Rate limiting
│   ├── Dockerfile
│   └── go.mod
├── waf-admin/                  # Admin Dashboard
│   ├── main.go                 # Веб-сервер
│   ├── static/                 # CSS, JS, images
│   ├── templates/              # HTML шаблоны
│   ├── Dockerfile
│   └── go.mod
├── waf-port-monitor.py         # Демон смены портов (HOST)
├── update-waf-port.sh          # Скрипт смены портов
├── PORT_CONFIGURATION.md       # Документация смены портов
└── README.md                   # Этот файл
```

### Разработка локально

**1. Клонировать и перейти в директорию**
```bash
git clone <repo>
cd Golang-Redis-Waf
```

**2. Запустить все сервисы**
```bash
docker-compose up --build
```

**3. Проверить логи**
```bash
# Все логи
docker-compose logs -f

# Конкретного сервиса
docker-compose logs -f wafproxy
docker-compose logs -f waf-admin
```

### Добавление новых правил защиты

**Файл:** `signaturedb/main.go`

```go
// Добавьте регулярное выражение в соответствующий массив

sqlPatterns := []string{
    `ваш-новый-паттерн-sql`,
    `(?i)EXEC\s*\(`,  // EXEC (для SQL Server)
}

xssPatterns := []string{
    `ваш-новый-паттерн-xss`,
    `(?i)eval\s*\(`,  // eval()
}

cmdiPatterns := []string{
    `ваш-новый-паттерн-cmdi`,
    `(?i)backtick`,  // backticks в Python/JS
}
```

Пересобрать контейнер:
```bash
docker-compose build signaturedb
docker-compose up -d signaturedb
```

### Изменение портов

**Метод 1: Через веб-интерфейс (рекомендуется)**
1. http://localhost:8080/config
2. Измените "Listen Port"
3. Save
4. Автоматически пересоздается через демон

**Метод 2: Через docker-compose**
```bash
WAF_PORT=9090 docker-compose up -d --force-recreate --no-deps wafproxy
```

**Метод 3: Через bash скрипт**
```bash
./update-waf-port.sh 9090
```

### Запуск тестов

```bash
# Протестировать SQL Injection protection
curl "http://localhost:8081/?id=' OR '1'='1'--"

# Проверить логи
docker-compose logs wafproxy | grep "PATTERN MATCHED"
```

---

## 🐛 Troubleshooting

### Контейнер не запускается

```bash
# Проверить логи
docker-compose logs wafproxy
docker-compose logs waf-admin

# Пересобрать образы
docker-compose build --no-cache
docker-compose up -d
```

### Redis не доступен

```bash
# Проверить статус Redis
docker-compose ps redis

# Переподключиться
docker-compose down
docker-compose up -d redis

# Проверить данные
docker-compose exec redis redis-cli ping
```

### Порт не меняется при смене конфигурации

```bash
# Проверить логи контейнера
docker-compose logs wafproxy | grep "Port change"

# Проверить демон
ps aux | grep waf-port-monitor.py

# Если демон не запущен:
python3 waf-port-monitor.py &

# Проверить Redis значение
redis-cli get waf:port:requested
```

### Контейнер падает при смене портов

```bash
# Убедиться что демон запущен
python3 waf-port-monitor.py &

# Проверить логи демона
# (смотреть в консоли где запущен python3)

# Проверить доступ к docker-compose
docker-compose --version

# Установить зависимости демона
pip3 install redis
```

### Защита не работает

```bash
# Проверить загружены ли сигнатуры в Redis
docker-compose exec redis redis-cli SMEMBERS waf:sqli

# Проверить включены ли модули
redis-cli get waf:module:sqli  # должно быть "1"

# Перезагрузить сигнатуры
docker-compose restart signaturedb
```

### Высокое потребление памяти

```bash
# Проверить использование памяти
docker stats

# Ограничить память в docker-compose.yml
# deploy:
#   resources:
#     limits:
#       memory: 512M

docker-compose up -d
```

---

## 📊 Мониторинг

### Метрики Redis

```bash
# Количество запросов
redis-cli get waf:stats:total_requests

# Заблокировано
redis-cli get waf:stats:blocked_requests

# Угрозы по типам
redis-cli get waf:stats:threats:sqli
redis-cli get waf:stats:threats:xss
redis-cli get waf:stats:threats:cmdi
redis-cli get waf:stats:threats:pathtraversal

# Последние логи
redis-cli lrange waf:logs 0 10
```

### Логирование

Все сервисы логируют в stdout (доступно через `docker-compose logs`):

```bash
# Следить за логами в реальном времени
docker-compose logs -f

# Только последние 50 строк
docker-compose logs --tail=50

# С временными метками
docker-compose logs -t
```

---

## 🔒 Безопасность

### Best Practices

1. **Используйте HTTPS** для защиты админ-панели
2. **Ограничьте доступ** к Redis только локально
3. **Установите firewall** правила на порты 8080, 8081, 8082, 8083
4. **Регулярно обновляйте** правила защиты
5. **Мониторьте логи** на предмет аномалий

### Защита админ-панели

Добавить базовую аутентификацию (todo в будущих версиях):
```go
// В waf-admin/main.go
// Реализовать middleware для проверки credentials
```

---

## 📄 Лицензия

MIT License - смотрите [LICENSE](LICENSE) файл для деталей.

---

## 🤝 Контрибьютинг

Благодарим за интерес к проекту! 

Процесс:
1. Fork репозиторий
2. Создать feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit изменения (`git commit -m 'Add some AmazingFeature'`)
4. Push в branch (`git push origin feature/AmazingFeature`)
5. Открыть Pull Request

---

## 📞 Поддержка

Если у вас есть вопросы или проблемы:

1. Проверьте [Troubleshooting](#-troubleshooting) раздел
2. Посмотрите [PORT_CONFIGURATION.md](PORT_CONFIGURATION.md) для смены портов
3. Проверьте логи: `docker-compose logs`
4. Откройте Issue на GitHub

---

## 🎉 Спасибо

Спасибо за использование NexusWAF!

**Последнее обновление:** 30 декабря 2025  
**Версия:** 1.0  
**Статус:** Production Ready ✅
