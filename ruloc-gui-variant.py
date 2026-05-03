#!/usr/bin/env python3
"""
ruloc-gui-variant.py - GUI tool for monitoring and blocking non-Russian connections
Features radar-style visualization with rotating pulsating scan arrow and country rays
"""

import time
import threading
import psutil
import geoip2.database
import subprocess
import argparse
import math
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
from collections import defaultdict
import numpy as np

# Path to database
GEOIP_DB_PATH = 'GeoLite2-Country.mmdb'

# Country ray mapping (angle in degrees, color)
# Predefined rays for common countries
COUNTRY_RAYS = {
    'RU': {'angle': 0, 'color': '#00ff00', 'name': 'Russia (Allowed)'},
    'US': {'angle': 30, 'color': '#ff4444', 'name': 'USA'},
    'CN': {'angle': 60, 'color': '#ff4444', 'name': 'China'},
    'DE': {'angle': 90, 'color': '#ffaa44', 'name': 'Germany'},
    'GB': {'angle': 120, 'color': '#ffaa44', 'name': 'United Kingdom'},
    'FR': {'angle': 150, 'color': '#ffaa44', 'name': 'France'},
    'JP': {'angle': 180, 'color': '#ffaa44', 'name': 'Japan'},
    'KR': {'angle': 200, 'color': '#ffaa44', 'name': 'South Korea'},
    'NL': {'angle': 220, 'color': '#ffaa44', 'name': 'Netherlands'},
    'BR': {'angle': 240, 'color': '#ffaa44', 'name': 'Brazil'},
    'IN': {'angle': 260, 'color': '#ffaa44', 'name': 'India'},
    'AU': {'angle': 280, 'color': '#ffaa44', 'name': 'Australia'},
    'CA': {'angle': 300, 'color': '#ffaa44', 'name': 'Canada'},
    'UA': {'angle': 320, 'color': '#ff8833', 'name': 'Ukraine'},
    'PL': {'angle': 340, 'color': '#ffaa44', 'name': 'Poland'},
}

# Default angles for unknown countries
UNKNOWN_NON_RU_ANGLE = 180  # Unknown non-Russia countries at 180°
UNKNOWN_RU_ANGLE = 0  # Unknown RU at 0° (shouldn't happen but for completeness)

class IPConnection:
    """Class to store IP connection information"""
    def __init__(self, ip, country, pid, timestamp):
        self.ip = ip
        self.country = country
        self.pid = pid
        self.timestamp = timestamp
        self.process_name = self.get_process_name()

    def get_process_name(self):
        try:
            if self.pid:
                proc = psutil.Process(self.pid)
                return proc.name()
        except:
            pass
        return 'Unknown'

class RadarMonitorGUI:
    def __init__(self, root, args):
        self.root = root
        self.args = args
        self.root.title("RULOC - Network Security Monitor")
        self.root.geometry("1400x900")

        # Set dark theme
        self.root.configure(bg='#1a1a2e')

        # Data structures
        self.connections = {}  # ip -> IPConnection
        self.blocked_ips = set()
        self.monitoring = True
        self.last_scan_time = 0
        self.connection_history = []

        # Colors
        self.bg_color = '#1a1a2e'
        self.radar_bg = '#0a0a1a'

        # Animation variables
        self.rotation_angle = 0
        self.pulse_alpha = 1.0
        self.pulse_direction = -1  # -1 for fading out, 1 for fading in
        self.last_pulse_time = time.time()

        # Country based angles for the radar (extend as needed)
        self.country_angle_map = self.build_country_angle_map()

        # Create GUI
        self.create_widgets()

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_connections, daemon=True)
        self.monitor_thread.start()

        # Start radar animation
        self.setup_radar()

    def build_country_angle_map(self):
        """Build angle mapping for countries"""
        angle_map = {}
        for code, data in COUNTRY_RAYS.items():
            angle_map[code] = data['angle']
        return angle_map

    def get_country_angle(self, country_code):
        """Get angle for a country code"""
        if country_code == 'RU':
            return 0  # Russia always at 0°
        elif country_code in self.country_angle_map:
            return self.country_angle_map[country_code]
        else:
            # Unknown non-Russia countries at 180°
            return UNKNOWN_NON_RU_ANGLE

    def get_country_color(self, country_code):
        """Get color for a country"""
        if country_code == 'RU':
            return '#00ff00'  # Green for Russia
        elif country_code in COUNTRY_RAYS:
            return COUNTRY_RAYS[country_code]['color']
        else:
            return '#ff6666'  # Red for unknown countries (non-RU)

    def get_country_name(self, country_code):
        """Get display name for country"""
        if country_code == 'RU':
            return 'Russia'
        elif country_code in COUNTRY_RAYS:
            return COUNTRY_RAYS[country_code]['name']
        return country_code or 'Unknown Country'

    def create_widgets(self):
        """Create all GUI widgets"""

        # Main container with padding
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left panel - Radar visualization
        left_panel = tk.Frame(main_frame, bg=self.bg_color)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # Radar frame
        radar_frame = tk.LabelFrame(left_panel, text="Radar Monitor",
                                     fg='#00ff00', bg=self.bg_color, font=('Arial', 12, 'bold'))
        radar_frame.pack(fill=tk.BOTH, expand=True)

        # Create matplotlib figure for radar
        self.fig = Figure(figsize=(8, 8), facecolor=self.radar_bg, dpi=100)
        self.ax = self.fig.add_subplot(111, polar=True)
        self.ax.set_facecolor(self.radar_bg)
        self.ax.set_title("Real-Time Network Radar Scanner", color='#00ff00', fontsize=14, pad=20)

        # Style the radar
        self.ax.set_theta_zero_location('N')
        self.ax.set_theta_direction(-1)  # Counter-clockwise for angle display

        # Set radial limits
        self.ax.set_ylim(0, 10)
        self.ax.set_yticks([2, 4, 6, 8, 10])
        self.ax.set_yticklabels(['2', '4', '6', '8', '10'], color='#444444', fontsize=8)
        self.ax.tick_params(axis='x', colors='#444444', labelsize=8)

        # Add circular grid lines
        for r in [2, 4, 6, 8, 10]:
            circle = plt.Circle((0, 0), r, transform=self.ax.transData._b,
                               fill=False, color='#00ff00', alpha=0.1, linestyle='--')
            self.ax.add_patch(circle)

        # Add grid lines
        self.ax.grid(color='#00ff00', alpha=0.15, linestyle='--', linewidth=0.5)

        # Draw country rays
        self.draw_country_rays()

        # Add legend for country colors
        self.add_legend()

        # Create canvas for radar
        self.canvas = FigureCanvasTkAgg(self.fig, master=radar_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Right panel - Controls and logs
        right_panel = tk.Frame(main_frame, bg=self.bg_color, width=500)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))
        right_panel.pack_propagate(False)

        # Control panel
        control_frame = tk.LabelFrame(right_panel, text="Controls",
                                       fg='#00ff00', bg=self.bg_color, font=('Arial', 12, 'bold'))
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # Buttons
        btn_frame = tk.Frame(control_frame, bg=self.bg_color)
        btn_frame.pack(pady=10)

        self.stop_btn = tk.Button(btn_frame, text="⏸ Stop Monitoring", command=self.stop_monitoring,
                                   bg='#ff4444', fg='white', font=('Arial', 10, 'bold'), padx=10)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.start_btn = tk.Button(btn_frame, text="▶ Start Monitoring", command=self.start_monitoring,
                                    bg='#44aa44', fg='white', font=('Arial', 10, 'bold'),
                                    state=tk.DISABLED, padx=10)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = tk.Button(btn_frame, text="🗑 Clear Log", command=self.clear_log,
                                    bg='#ffaa44', fg='#1a1a2e', font=('Arial', 10, 'bold'), padx=10)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        # Stats frame
        stats_frame = tk.LabelFrame(right_panel, text="Statistics",
                                     fg='#00ff00', bg=self.bg_color, font=('Arial', 12, 'bold'))
        stats_frame.pack(fill=tk.X, pady=(0, 10))

        self.stats_text = tk.Text(stats_frame, height=7, bg='#0a0a1a', fg='#00ff00',
                                   font=('Courier', 10), wrap=tk.WORD)
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)

        # Connection list
        conn_frame = tk.LabelFrame(right_panel, text="Active Connections",
                                    fg='#00ff00', bg=self.bg_color, font=('Arial', 12, 'bold'))
        conn_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Treeview for connections
        columns = ('IP', 'Country', 'Process', 'PID', 'Time')
        self.conn_tree = ttk.Treeview(conn_frame, columns=columns, show='headings', height=10)

        # Configure treeview style
        style = ttk.Style()
        style.theme_use('default')
        style.configure("Treeview", background="#0a0a1a", foreground="#00ff00",
                       fieldbackground="#0a0a1a", font=('Courier', 9))
        style.configure("Treeview.Heading", background="#1a1a2e", foreground="#00ff00",
                       font=('Arial', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#00ff00')],
                 foreground=[('selected', '#1a1a2e')])

        for col in columns:
            self.conn_tree.heading(col, text=col)
            self.conn_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(conn_frame, orient=tk.VERTICAL, command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=scrollbar.set)

        self.conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Log panel
        log_frame = tk.LabelFrame(right_panel, text="Event Log",
                                   fg='#00ff00', bg=self.bg_color, font=('Arial', 12, 'bold'))
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, bg='#0a0a1a',
                                                    fg='#88ff88', font=('Courier', 9), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status bar
        self.status_bar = tk.Label(self.root, text="🟢 Monitoring Active | Radar Scanning...",
                                    bd=1, relief=tk.SUNKEN, anchor=tk.W,
                                    bg='#0a0a1a', fg='#00ff00', font=('Courier', 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Initial stats update
        self.update_stats()

    def draw_country_rays(self):
        """Draw rays for each country on the radar"""
        for country_code, data in COUNTRY_RAYS.items():
            angle_rad = math.radians(data['angle'])
            # Draw ray from center to outer edge (radius 10)
            self.ax.plot([angle_rad, angle_rad], [0, 10], color=data['color'],
                        linewidth=2, alpha=0.4, linestyle='-')
            # Add country label at outer edge
            label_angle = angle_rad
            label_radius = 10.5
            self.ax.text(label_angle, label_radius, data['name'][:3], color=data['color'],
                        fontsize=7, ha='center', va='center', alpha=0.8, fontweight='bold')

        # Add ray for unknown non-RU countries at 180°
        unknown_angle_rad = math.radians(UNKNOWN_NON_RU_ANGLE)
        self.ax.plot([unknown_angle_rad, unknown_angle_rad], [0, 10], color='#ff6666',
                    linewidth=2, alpha=0.4, linestyle='--')
        self.ax.text(unknown_angle_rad, 10.5, 'UNK', color='#ff6666',
                    fontsize=7, ha='center', va='center', alpha=0.8, fontweight='bold')

    def add_legend(self):
        """Add color legend to the radar"""
        legend_elements = []
        legend_elements.append(plt.Line2D([0], [0], color='#00ff00', lw=2, label='Russia (RU) - Allowed'))
        legend_elements.append(plt.Line2D([0], [0], color='#ff4444', lw=2, label='High Risk Countries'))
        legend_elements.append(plt.Line2D([0], [0], color='#ffaa44', lw=2, label='Medium Risk'))
        legend_elements.append(plt.Line2D([0], [0], color='#ff6666', lw=2, label='Unknown/Other Countries'))

        self.ax.legend(handles=legend_elements, loc='lower left', bbox_to_anchor=(-0.15, -0.1),
                      fontsize=8, facecolor=self.radar_bg, edgecolor='#00ff00',
                      labelcolor='#00ff00')

    def setup_radar(self):
        """Setup radar animation with rotating pulsating scan arrow (1 rotation per 3 seconds, clockwise)"""
        # Create the main scan line
        self.scan_line = None
        self.pulse_trail = []

        def animate(frame):
            if not self.monitoring:
                # Still animate but with dimmed line
                pass

            # Update rotation angle for CLOCKWISE rotation
            # Subtract to rotate clockwise (360 degrees per 3 seconds = 120 degrees per second)
            # At 30fps, each frame subtracts 4 degrees for clockwise rotation
            self.rotation_angle = (self.rotation_angle - 4) % 360

            # Update pulse alpha for pulsating effect
            current_time = time.time()
            dt = current_time - self.last_pulse_time
            self.last_pulse_time = current_time

            # Pulse speed (oscillate every 0.5 seconds)
            pulse_speed = 8.0
            self.pulse_alpha = 0.3 + 0.7 * (math.sin(time.time() * pulse_speed) ** 2)

            # Clear previous scan elements
            if self.scan_line:
                self.scan_line.remove()
            for trail in self.pulse_trail:
                if trail:
                    try:
                        trail.remove()
                    except:
                        pass
            self.pulse_trail = []

            # Draw rotating scan line (simple line from center to edge)
            angle_rad = math.radians(self.rotation_angle)

            # Simple line from center (0) to edge (10)
            self.scan_line, = self.ax.plot([angle_rad, angle_rad], [0, 10],
                                          color='#00ff00', linewidth=2.5,
                                          alpha=0.9, zorder=10)

            # Draw pulsating glow trail behind the scan line (clockwise trail)
            for i in range(5):
                # Trail follows clockwise (add angle for trail behind)
                trail_angle_deg = (self.rotation_angle + 8 * (i + 1)) % 360
                trail_rad = math.radians(trail_angle_deg)
                trail_alpha = max(0.05, min(0.5, self.pulse_alpha * (1 - i * 0.12)))

                trail_line, = self.ax.plot([trail_rad, trail_rad], [0, 9.5],
                                          color='#00ff00', linewidth=2,
                                          alpha=trail_alpha, zorder=5)
                self.pulse_trail.append(trail_line)

            # Update connection dots
            self.update_connection_dots()

            # Update connection list in GUI
            self.update_connection_list()
            self.update_stats()

            # Return all animated objects
            objects = [self.scan_line] + self.pulse_trail
            return objects

        self.anim = animation.FuncAnimation(self.fig, animate, interval=1000/30,  # ~30 FPS
                                            blit=False, cache_frame_data=False)

    def update_connection_dots(self):
        """Update the connection dots on the radar"""
        # Remove existing dots
        if hasattr(self, 'connection_dots'):
            for dot in self.connection_dots:
                if dot:
                    try:
                        dot.remove()
                    except:
                        pass

        self.connection_dots = []

        # Add dots for current connections
        now = time.time()
        for ip, conn in list(self.connections.items()):
            # Fade out older connections (alpha decreases with age)
            age = now - conn.timestamp
            if age > 30:  # Remove after 30 seconds
                continue

            # Fix: Ensure alpha is within valid range 0-1
            alpha = 1 - (age / 30)
            alpha = max(0.2, min(1.0, alpha))  # Clamp between 0.2 and 1.0

            angle = self.get_country_angle(conn.country)
            angle_rad = math.radians(angle)

            # Radius based on age (newer connections closer to center)
            # New connection: radius ~1, Old connection: radius ~9
            radius = 1 + (age / 30) * 8
            color = self.get_country_color(conn.country)

            # Add pulsing effect for new connections
            if age < 3:
                pulse = 0.5 + 0.5 * math.sin(time.time() * 10)
                size = 8 + pulse * 4
            else:
                size = 6

            dot = self.ax.plot(angle_rad, radius, 'o', color=color,
                              markersize=size, alpha=alpha, zorder=15)
            self.connection_dots.extend(dot)

    def get_connection_country(self, ip):
        """Get country for IP address"""
        try:
            with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
                response = reader.country(ip)
                return response.country.iso_code
        except Exception:
            return None

    def block_ip_ufw(self, ip):
        """Block IP using UFW"""
        if ip in self.blocked_ips:
            return
        try:
            subprocess.run(['sudo', 'ufw', 'deny', 'from', ip],
                         check=True, capture_output=True)
            self.blocked_ips.add(ip)
            self.add_to_log(f"🔒 BLOCKED: {ip} added to UFW firewall", '#ff4444')
            print(f"UFW rule added: blocked {ip}")
        except subprocess.CalledProcessError as e:
            self.add_to_log(f"⚠ ERROR: Failed to block {ip}: {e}", '#ff8844')
            print(f"Error adding UFW rule: {e}")

    def kill_process(self, pid, ip):
        """Terminate process by PID"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            self.add_to_log(f"✂ TERMINATED: Process {proc_name} (PID: {pid}) from {ip}", '#ffaa44')
            print(f"Process {pid} terminated (IP: {ip})")
        except Exception as e:
            self.add_to_log(f"⚠ ERROR: Failed to terminate PID {pid}: {e}", '#ff8844')

    def add_to_log(self, message, color='#88ff88'):
        """Add message to log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}\n"

        # Insert with color tag
        self.log_text.insert(tk.END, formatted)
        # Auto-scroll to bottom
        self.log_text.see(tk.END)

        # Also print to console for debugging
        print(formatted.strip())

    def update_connection_list(self):
        """Update the connection treeview"""
        # Clear existing items
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)

        # Add current connections
        now = time.time()
        for ip, conn in sorted(self.connections.items(), key=lambda x: x[1].timestamp, reverse=True):
            age = now - conn.timestamp
            if age > 30:
                continue

            time_str = datetime.fromtimestamp(conn.timestamp).strftime("%H:%M:%S")
            country_display = f"{conn.country or '??'}"
            country_full = self.get_country_name(conn.country)

            # Color code based on country
            if conn.country == 'RU':
                tags = ('ru',)
            elif conn.country and conn.country not in COUNTRY_RAYS:
                tags = ('unknown',)
            else:
                tags = ('other',)

            self.conn_tree.insert('', tk.END, values=(
                conn.ip,
                f"{country_display} ({country_full[:15]})",
                conn.process_name[:20],
                conn.pid or 'N/A',
                time_str
            ), tags=tags)

        # Configure tag colors
        self.conn_tree.tag_configure('ru', foreground='#00ff00')
        self.conn_tree.tag_configure('unknown', foreground='#ff6666')
        self.conn_tree.tag_configure('other', foreground='#ffaa44')

    def update_stats(self):
        """Update statistics display with proper table formatting"""
        now = time.time()
        active_conns = sum(1 for c in self.connections.values() if now - c.timestamp <= 30)
        non_ru_conns = sum(1 for c in self.connections.values()
                          if now - c.timestamp <= 30 and c.country and c.country != 'RU')
        blocked_count = len(self.blocked_ips)

        # Calculate connections by region
        ru_count = sum(1 for c in self.connections.values()
                      if now - c.timestamp <= 30 and c.country == 'RU')
        unknown_count = sum(1 for c in self.connections.values()
                           if now - c.timestamp <= 30 and c.country and c.country not in COUNTRY_RAYS)

        stats = f""" Monitoring:         {'● ACTIVE' if self.monitoring else '○ STOPPED'}
Active Connections: {active_conns:3} Russia (RU):      {ru_count:3}
Non-RU: {non_ru_conns:3} Unknown: {unknown_count:3}
Blocked IPs: {blocked_count:3}
"""

        # Update stats text
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats)

        # Update status bar
        self.status_bar.config(text=f"🟢 Active: {active_conns} | 🚫 Non-RU: {non_ru_conns} | 🔒 Blocked: {blocked_count} | 🔄 Scan: 1 rotation/3sec (Clockwise)")

    def monitor_connections(self):
        """Main monitoring loop"""
        print("🟢 Monitoring started. Only connections from RU are allowed.")
        self.add_to_log("🟢 MONITORING STARTED - Only RU connections allowed | Radar scanning at 1 rotation/3sec (Clockwise)", '#00ff00')

        while True:
            if not self.monitoring:
                time.sleep(1)
                continue

            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        ip = conn.raddr.ip

                        # Update or add connection
                        if ip not in self.connections:
                            country = self.get_connection_country(ip)
                            self.connections[ip] = IPConnection(ip, country, conn.pid, time.time())

                            # Check if non-RU connection
                            if country and country != 'RU':
                                self.add_to_log(f"⚠ DETECTED: Connection from {country} - {ip} (PID: {conn.pid})", '#ff8888')
                                print(f"⚠ Connection detected from {country}: {ip}")

                                if self.args.ufw_block_detected:
                                    self.block_ip_ufw(ip)

                                if self.args.close_proc and conn.pid:
                                    self.kill_process(conn.pid, ip)
                            elif not country:
                                self.add_to_log(f"❓ UNKNOWN COUNTRY: Connection from IP {ip} (PID: {conn.pid})", '#ffaa66')
                        else:
                            # Update timestamp for existing connection
                            self.connections[ip].timestamp = time.time()

                # Clean up old connections
                now = time.time()
                to_remove = [ip for ip, conn in self.connections.items()
                            if now - conn.timestamp > 30]
                for ip in to_remove:
                    del self.connections[ip]

            except Exception as e:
                print(f"⚠ Monitor error: {e}")

            time.sleep(2)

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        self.stop_btn.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.NORMAL)
        self.add_to_log("⏸ Monitoring STOPPED - Radar scan paused", '#ffaa44')

    def start_monitoring(self):
        """Start monitoring"""
        self.monitoring = True
        self.stop_btn.config(state=tk.NORMAL)
        self.start_btn.config(state=tk.DISABLED)
        self.add_to_log("▶ Monitoring RESUMED - Radar scan active (1 rotation/3sec, clockwise)", '#00ff00')

    def clear_log(self):
        """Clear the log"""
        self.log_text.delete(1.0, tk.END)
        self.add_to_log("📋 Log cleared", '#888888')

    def on_closing(self):
        """Handle window closing"""
        self.monitoring = False
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="RULOC GUI - Network Security Monitor with Radar Scanner")
    parser.add_argument('--ufw-block-detected', action='store_true',
                       help="Block IPs via UFW automatically")
    parser.add_argument('--close-proc', action='store_true',
                       help="Terminate processes for non-RU connections")
    args = parser.parse_args()

    # Create GUI
    root = tk.Tk()
    app = RadarMonitorGUI(root, args)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
