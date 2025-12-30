#!/usr/bin/env python3

"""
Docker WAF Port Update Monitor
Отслеживает изменения требуемого порта в Redis и пересоздает контейнер
"""

import os
import subprocess
import time
import redis
import sys
from pathlib import Path

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))
COMPOSE_DIR = os.getenv('COMPOSE_DIR', os.path.dirname(os.path.abspath(__file__)))
CONTAINER_NAME = 'wafproxy'
POLLING_INTERVAL = 5

def get_redis_client():
    """Получить подключение к Redis"""
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
        r.ping()
        return r
    except Exception as e:
        print(f"Error connecting to Redis: {e}")
        return None

def get_current_port():
    """Получить текущий порт из переменной окружения"""
    return os.getenv('WAF_PORT', '8081')

def get_requested_port(r):
    """Получить требуемый порт из Redis"""
    try:
        if r is None:
            return None
        port = r.get('waf:port:requested')
        return port
    except Exception as e:
        print(f"Error reading from Redis: {e}")
        return None

def get_container_id():
    """Получить ID контейнера по имени"""
    try:
        result = subprocess.run(
            ['docker', 'ps', '-q', '-f', f'name={CONTAINER_NAME}'],
            capture_output=True,
            text=True,
            timeout=5
        )
        container_id = result.stdout.strip()
        return container_id if container_id else None
    except Exception as e:
        print(f"Error getting container ID: {e}")
        return None

def update_container_port(new_port):
    """Обновить порт контейнера через docker-compose"""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Updating WAF proxy port to {new_port}")
    
    try:
        # Устанавливаем переменную окружения
        env = os.environ.copy()
        env['WAF_PORT'] = new_port
        
        # Пересоздаем контейнер
        result = subprocess.run(
            ['docker-compose', 'up', '-d', '--force-recreate', '--no-deps', 'wafproxy'],
            cwd=COMPOSE_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Successfully updated WAF proxy port to {new_port}")
            return True
        else:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error updating port: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Timeout while updating container")
        return False
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error updating container: {e}")
        return False

def main():
    """Основной цикл мониторинга"""
    print(f"WAF Port Update Monitor started")
    print(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    print(f"Compose Dir: {COMPOSE_DIR}")
    print(f"Polling interval: {POLLING_INTERVAL}s")
    
    # Проверяем что docker-compose доступен
    try:
        subprocess.run(['docker-compose', '--version'], capture_output=True, timeout=5, check=True)
    except Exception as e:
        print(f"Error: docker-compose not available: {e}")
        sys.exit(1)
    
    r = get_redis_client()
    if r is None:
        print("Warning: Redis not available, continuing without port sync...")
    
    last_port = None
    
    while True:
        try:
            # Получаем требуемый порт из Redis
            requested_port = get_requested_port(r) if r else None
            
            if requested_port and requested_port != last_port:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Port change detected: {last_port} -> {requested_port}")
                
                # Обновляем контейнер
                if update_container_port(requested_port):
                    last_port = requested_port
                    # Очищаем флаг в Redis
                    if r:
                        try:
                            r.delete('waf:port:requested')
                        except:
                            pass
                else:
                    print(f"Failed to update container, will retry...")
            
            time.sleep(POLLING_INTERVAL)
            
        except KeyboardInterrupt:
            print("\nMonitor stopped by user")
            break
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error in main loop: {e}")
            time.sleep(POLLING_INTERVAL)

if __name__ == '__main__':
    main()
