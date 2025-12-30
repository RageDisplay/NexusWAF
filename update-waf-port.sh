#!/bin/bash

# Скрипт для обновления порта wafproxy контейнера
# Использование: ./update-waf-port.sh <новый_порт>

NEW_PORT=$1

if [ -z "$NEW_PORT" ]; then
    echo "Usage: $0 <new_port>"
    exit 1
fi

echo "Updating WAF proxy port to $NEW_PORT"

# Устанавливаем переменную окружения и пересоздаем контейнер
export WAF_PORT=$NEW_PORT

# Пересоздаем контейнер через docker-compose
docker-compose up -d --force-recreate --no-deps wafproxy

if [ $? -eq 0 ]; then
    echo "Successfully updated WAF proxy port to $NEW_PORT"
    exit 0
else
    echo "Failed to update WAF proxy port"
    exit 1
fi
