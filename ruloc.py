import time
import psutil
import geoip2.database
import subprocess
import argparse

# Путь к базе данных
GEOIP_DB_PATH = 'GeoLite2-Country.mmdb'

def get_connection_country(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip)
            return response.country.iso_code
    except Exception:
        return None

def block_ip_ufw(ip):
    try:
        # Добавление правила блокировки в UFW
        subprocess.run(['sudo', 'ufw', 'deny', 'from', ip], check=True)
        print(f"Правило UFW добавлено: заблокирован {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при добавлении правила UFW: {e}")

def kill_process(pid, ip):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"Процесс {pid} завершен (IP: {ip})")
    except Exception as e:
        print(f"Ошибка при завершении процесса {pid}: {e}")

def monitor(args):
    print("Мониторинг запущен. Разрешены только соединения из RU.")
    try:
        while True:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    country = get_connection_country(ip)

                    if country and country != 'RU':
                        print(f"Обнаружено соединение из {country}: {ip}")

                        if args.ufw_block_detected:
                            block_ip_ufw(ip)

                        if args.close_proc and conn.pid:
                            kill_process(conn.pid, ip)

            time.sleep(3)
    except KeyboardInterrupt:
        print("Мониторинг остановлен.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Мониторинг соединений и блокировка IP.")
    parser.add_argument('--ufw-block-detected', action='store_true', help="Блокировать IP через UFW.")
    parser.add_argument('--close-proc', action='store_true', help="Завершать процесс для IP.")
    args = parser.parse_args()

    monitor(args)
