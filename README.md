# RULOC - Network Security Monitor

RULOC is a network monitoring tool that tracks active TCP connections and automatically responds to connections from countries other than Russia. It comes in two versions: a command-line interface (CLI) tool and a graphical user interface (GUI) tool with a real-time radar visualization.

## Screenshot

[ruloc GUI](https://dl.dropbox.com/scl/fi/fyyswrd2meloomerrtue5/ruloc-gui-variant.png?rlkey=gzhkr6k60tts65dr14vdiirqr&st=ilnlq8g5)

## Features

- Real-time monitoring of active TCP connections
- Country lookup by IP address (uses GeoLite2 database)
- Automatic IP blocking via `ufw`
- Termination of processes with unwanted connections
- Only connections from `RU` are considered allowed

### GUI Version Additional Features:
- **Radar-style visualization** with rotating scan line
- **Country rays** at fixed angles for easy identification
- **Real-time connection dots** that appear on the radar
- **Pulsating scan trail** with clockwise rotation (1 rotation per 3 seconds)
- **Color-coded threats** (green for RU, red for high-risk, yellow for medium-risk)
- **Live statistics panel** with connection counts
- **Event log** with timestamped messages
- **Interactive controls** (Start/Stop monitoring, Clear log)

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
# For CLI version
pip install psutil geoip2

# For GUI version (includes matplotlib for radar visualization)
pip install psutil geoip2 matplotlib
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

### CLI Version (ruloc.py)

#### Basic syntax

```bash
python3 ruloc.py [--ufw-block-detected] [--close-proc]
```

#### Usage examples

**Block IP via UFW only:**
```bash
python3 ruloc.py --ufw-block-detected
```

**Terminate processes only:**
```bash
python3 ruloc.py --close-proc
```

**Both blocking and process termination:**
```bash
python3 ruloc.py --ufw-block-detected --close-proc
```

**Run in background:**
```bash
nohup python3 ruloc.py --ufw-block-detected --close-proc &
```

### GUI Version (ruloc-gui-variant.py)

#### Basic syntax

```bash
python3 ruloc-gui-variant.py [--ufw-block-detected] [--close-proc]
```

#### Usage examples

**Monitor only (no automatic actions):**
```bash
python3 ruloc-gui-variant.py
```

**Monitor and block IPs via UFW:**
```bash
python3 ruloc-gui-variant.py --ufw-block-detected
```

**Monitor and terminate processes:**
```bash
python3 ruloc-gui-variant.py --close-proc
```

**Full protection (block + terminate):**
```bash
python3 ruloc-gui-variant.py --ufw-block-detected --close-proc
```

#### GUI Interface Overview

When launched, the GUI window displays:

1. **Left Panel - Radar Monitor:**
   - Rotating radar scanner (clockwise, 1 rotation per 3 seconds)
   - Colored rays for different countries at fixed angles:
     - 0° (Top): Russia (RU) - Green
     - 30°: USA - Red
     - 60°: China - Red
     - 90°: Germany - Yellow
     - 120°: UK - Yellow
     - 150°: France - Yellow
     - 180°: Japan, Unknown countries - Yellow/Red
     - 200°-340°: Other countries
   - Colored dots representing active connections
   - New connections appear closer to the center
   - Connections fade out after 30 seconds

2. **Right Panel:**
   - **Controls:** Stop/Start monitoring, Clear log buttons
   - **Statistics:** Active/RU/Non-RU/Unknown connection counts, blocked IPs
   - **Active Connections:** Table with IP, Country, Process, PID, Time
   - **Event Log:** Timestamped log of all detected events

3. **Status Bar:**
   - Shows current connection counts and scan status

#### Keyboard Shortcuts

- `Ctrl+C` in terminal (CLI version) - Stop monitoring
- Close window (GUI version) - Exit application

## How It Works

### CLI Version
1. The script scans all established TCP connections every 3 seconds
2. For each remote IP, it determines the country using the GeoIP database
3. If the country is not `RU`:
   - A message is printed to the console
   - With `--ufw-block-detected`, adds a `ufw deny from <IP>` rule
   - With `--close-proc`, terminates the process owning the connection

### GUI Version
1. Same monitoring logic as CLI version
2. Visualizes connections on a polar radar plot:
   - Angle determined by country (Russia at 0°, unknown non-RU at 180°)
   - Radius determined by connection age (newer = closer to center)
   - Dot color indicates risk level
3. Animated scan line rotates clockwise at 120° per second
4. Pulsating trail shows recent scan path
5. Real-time updates to connection table and statistics

## Country Risk Levels

- **🟢 Green (Russia - RU):** Allowed connections
- **🔴 Red (High Risk):** USA, China, and other high-risk countries
- **🟡 Yellow (Medium Risk):** Germany, UK, France, Japan, etc.
- **🔴 Red (Unknown):** Unknown countries are treated as non-RU and appear at 180°

## Important Notes

- The script does not distinguish between incoming and outgoing connections — it checks **all** established connections
- UFW blocking is permanent until the rule is manually removed
- Process termination can be dangerous — use the `--close-proc` option with caution on production servers
- An up-to-date GeoIP database is required for correct operation
- GUI version requires an X11 display server (works on Linux desktop environments)
- The radar visualization shows connections for 30 seconds after they close

## View UFW added rules

```bash
sudo ufw status numbered
```

## Remove UFW rules

```bash
sudo ufw delete <rule_number>
```

## Stop the script

**CLI version:**
Press `Ctrl+C` in the terminal

**GUI version:**
- Click the "Stop Monitoring" button, then close the window
- Or simply close the window

**Force stop (both versions):**
```bash
pkill -f ruloc
```

## Troubleshooting

### GUI won't start or shows import error
Make sure you have matplotlib installed:
```bash
pip install matplotlib
```

### Alpha value error in GUI
This has been fixed in the latest version. Make sure you're using the updated script with proper alpha clamping.

### GeoIP database not found
Download the database file and place it in the same directory as the script:
```bash
wget https://github.com/P3TERX/GeoLite2.mmdb/raw/master/GeoLite2-Country.mmdb
```

### Permission denied for UFW
Make sure you've configured sudo permissions correctly or run with sudo:
```bash
sudo python3 ruloc.py --ufw-block-detected
```

### No connections showing on radar
The radar only shows connections that are currently established. Run some network activity (browse websites, use curl, etc.) to see connections appear.

## Performance Considerations

- **CLI Version:** Minimal system impact (~5-10% CPU on a single core)
- **GUI Version:** Moderate system impact (~10-20% CPU due to animation)
- Both versions use ~50-100 MB of RAM depending on connection count

## Remove virtual environment

```bash
deactivate
rm -rf venv
```

## License

MIT
