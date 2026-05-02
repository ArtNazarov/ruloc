# RULOC - Monitor and Block Non-Russian Connections

The `ruloc.py` script monitors established TCP connections on your server and automatically responds to connections from countries other than Russia. It can block IP addresses via `ufw` and/or terminate processes that initiated unwanted connections.

## Features

- Real-time monitoring of active TCP connections
- Country lookup by IP address (uses GeoLite2 database)
- Automatic IP blocking via `ufw`
- Termination of processes with unwanted connections
- Only connections from `RU` are considered allowed

## Requirements

- Python 3.6+
- Linux with `ufw` (for blocking)
- `sudo` privileges (for adding `ufw` rules)
- `GeoLite2-Country.mmdb` database file in the script directory

## Installation and Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd <project-directory>
```

### 2. Set up a virtual environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate   # For Linux/macOS
# or
venv\Scripts\activate      # For Windows (if running locally)
```

### 3. Install dependencies

```bash
pip install psutil geoip2
```

### 4. Download the GeoIP database

Download the free `GeoLite2-Country.mmdb` database from the [official MaxMind website](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place it in the script directory.

```bash
wget https://github.com/P3TERX/GeoLite2.mmdb/raw/master/GeoLite2-Country.mmdb
```

### 5. Configure sudo permissions

For UFW blocking to work, the script requires `sudo` privileges without a password prompt (recommended only for the specific command):

```bash
sudo visudo -f /etc/sudoers.d/ufw-ruloc
```

Add this line:
```
your_username ALL=(ALL) NOPASSWD: /usr/sbin/ufw deny from *
```

## Usage

### Basic syntax

```bash
python3 ruloc.py [--ufw-block-detected] [--close-proc]
```

### Usage examples

#### Block IP via UFW only

```bash
python3 ruloc.py --ufw-block-detected
```

#### Terminate processes only

```bash
python3 ruloc.py --close-proc
```

#### Both blocking and process termination

```bash
python3 ruloc.py --ufw-block-detected --close-proc
```

### Run in background

```bash
nohup python3 ruloc.py --ufw-block-detected --close-proc &
```

Or using `screen`/`tmux`:

```bash
screen -S ruloc
python3 ruloc.py --ufw-block-detected --close-proc
# Ctrl+A, D - detach
```

## How it works

1. The script scans all established TCP connections every 3 seconds
2. For each remote IP, it determines the country using the GeoIP database
3. If the country is not `RU`:
   - A message is printed to the console
   - With `--ufw-block-detected`, adds a `ufw deny from <IP>` rule
   - With `--close-proc`, terminates the process owning the connection

## Important Notes

- The script does not distinguish between incoming and outgoing connections — it checks **all** established connections
- UFW blocking is permanent until the rule is manually removed
- Process termination can be dangerous — use the `--close-proc` option with caution on production servers
- An up-to-date GeoIP database is required for correct operation

## View UFW added rules

```bash
sudo ufw status numbered
```

## Remove UFW rules

```bash
sudo ufw delete <rule_number>
```

## Stop the script

Press `Ctrl+C` in the terminal or kill the process:

```bash
pkill -f ruloc.py
```

## Remove virtual environment

```bash
deactivate
rm -rf venv
```

## License

MIT
