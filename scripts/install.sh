#!/bin/bash
# Universal Quick Share — desktop integration (XFCE-oriented, works on any freedesktop session)
# Installs: uqs + uqs-gui binaries, app launcher, tray autostart, Thunar right-click action.
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HOME/.local/bin/uqs"
GUI="$HOME/.local/bin/uqs-gui"
mkdir -p "$HOME/.local/bin"
# Ask a running GUI to exit first, and replace binaries by rename: a plain cp over a
# running executable fails with "Text file busy".
[ -x "$GUI" ] && "$GUI" --quit >/dev/null 2>&1 || true
sleep 1
pick() { [ -x "$DIR/target/release/$1" ] && echo "$DIR/target/release/$1" || echo "$DIR/target/debug/$1"; }
cp "$(pick uqs)" "$BIN.tmp" && mv -f "$BIN.tmp" "$BIN"
cp "$(pick uqs-gui)" "$GUI.tmp" && mv -f "$GUI.tmp" "$GUI"

# --- The GUI owns receiving now. Retire the headless CLI daemon so the two never
#     advertise the same endpoint at once (same hostname-derived endpoint ID + BLE path).
if systemctl --user list-unit-files uqs.service >/dev/null 2>&1; then
  systemctl --user disable --now uqs.service >/dev/null 2>&1 || true
  rm -f "$HOME/.config/systemd/user/uqs.service"
  systemctl --user daemon-reload
  echo "• retired headless uqs.service (uqs-gui replaces it)"
fi

# --- App launcher + autostart (XFCE session autostart has DISPLAY/DBUS; user systemd
#     units do not reliably, and graphical-session.target never activates on XFCE).
mkdir -p "$HOME/.local/share/applications" "$HOME/.config/autostart"
sed "s|^Exec=uqs-gui|Exec=$GUI|" "$DIR/scripts/uqs-gui.desktop" > "$HOME/.local/share/applications/uqs-gui.desktop"
sed -e "s|^Exec=uqs-gui.*|Exec=$GUI --hidden|" -e "s|^Name=.*|Name=Quick Share (tray)|" \
    "$DIR/scripts/uqs-gui.desktop" > "$HOME/.config/autostart/uqs-gui.desktop"
echo "X-GNOME-Autostart-enabled=true" >> "$HOME/.config/autostart/uqs-gui.desktop"
update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
echo "✔ launcher installed (menu: Quick Share) + autostart in tray at login"

# Start the freshly installed binary in the tray.
"$GUI" --hidden >/dev/null 2>&1 &
disown || true
echo "✔ uqs-gui running in the tray (click the icon or run: uqs-gui)"

# --- Thunar custom action: right-click → "Send via Quick Share" ---
UCA="$HOME/.config/Thunar/uca.xml"
if [ -f "$UCA" ]; then
  if grep -q "uqs send-gui" "$UCA"; then
    # Older installs used the CLI picker; point the existing action at the GUI instead.
    sed -i "s|<command>uqs send-gui %F</command>|<command>uqs-gui %F</command>|" "$UCA"
    echo "✔ Thunar action updated to launch the GUI"
  elif ! grep -q "<command>uqs-gui %F</command>" "$UCA"; then
    ACTION='	<action>
		<icon>document-send</icon>
		<name>Send via Quick Share</name>
		<unique-id>uqs-send-gui-1</unique-id>
		<command>uqs-gui %F</command>
		<description>Send selected files to a nearby Quick Share device</description>
		<patterns>*</patterns>
		<directories/>
		<audio-files/>
		<image-files/>
		<other-files/>
		<text-files/>
		<video-files/>
	</action>'
    # insert before closing </actions>
    python3 - "$UCA" "$ACTION" <<'PY'
import sys
path, action = sys.argv[1], sys.argv[2]
s = open(path).read()
s = s.replace("</actions>", action + "\n</actions>")
open(path, "w").write(s)
PY
    echo "✔ Thunar action added (restart Thunar or log out/in to see it)"
  else
    echo "• Thunar action already present"
  fi
else
  echo "• No Thunar uca.xml found; open Thunar → Edit → Configure Custom Actions and add:"
  echo "    uqs-gui %F"
fi

echo
echo "Receiving is always-on in the tray: shares from your phone open the Quick Share window."
echo "Send files: right-click in Thunar → Send via Quick Share, drag onto the window, or: uqs-gui <file>"
echo "Send clipboard (text, link, or copied files): uqs-gui --clipboard"
