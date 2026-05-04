#!/bin/bash
set -e

# 1. Clean up stale X locks from previous container runs
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0 2>/dev/null

# 2. Fix /tmp permissions required by Xvfb
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix
chown root:root /tmp/.X11-unix

# 3. Ensure application directories exist and are owned by i2iuser
#    so that key persistence, file reception, and logging work correctly
mkdir -p /app/keys /app/received_files /app/logs
chown -R i2iuser:i2igroup /app/keys /app/received_files /app/logs

# 4. Start the display stack as root (required for device access)
Xvfb :0 -screen 0 1280x900x24 &
while [ ! -S /tmp/.X11-unix/X0 ]; do sleep 0.1; done

fluxbox -display :0 &
x11vnc -display :0 -nopw -forever -shared -quiet &
websockify --web /usr/share/novnc/ 6080 localhost:5900 &

export DISPLAY=:0

# 5. Drop privileges and run the Python client as i2iuser
exec gosu i2iuser python main.py
