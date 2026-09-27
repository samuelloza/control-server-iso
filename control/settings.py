"""Configuracion: rutas, limites y acciones permitidas."""
import os
import re


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # raiz del repo


def _env_path(name, default):
    return os.path.abspath(os.environ.get(name, os.path.join(HERE, default)))


DB_PATH = _env_path("CONTROL_DB", "data/control.db")


SIGNING_KEY = _env_path("CONTROL_SIGNING_KEY", "keys/command-signing.key")


GROUPS_FILE = _env_path("CONTROL_GROUP_TOKENS", "groups.json")


USERS_FILE = os.environ.get("AUTH_USERS", os.path.join(HERE, "users.json"))


INDEX_HTML = os.path.join(HERE, "index.html")


BRAND_LOGO_SVG = os.path.join(HERE, "icpc-bolivia-logo.svg")


BRAND_WALLPAPER_SVG = os.path.join(HERE, "icpc-bolivia-wallpaper.svg")


BIND = os.environ.get("CONTROL_BIND", "127.0.0.1:8090")


ADMIN_TOKEN = os.environ.get("CONTROL_ADMIN_TOKEN", "")


DEFAULT_HOMEPAGE = os.environ.get(
    "AUTH_DEFAULT_HOMEPAGE", "file:///usr/share/doc/contest/index.html")


COMMAND_TTL_SECONDS = int(os.environ.get("CONTROL_COMMAND_TTL", "3600"))


LONGPOLL_MAX = 30


SAMPLES_PER_MACHINE = 400


JOURNAL_BYTES_PER_MACHINE = 65536


SCREENSHOT_DIR = _env_path("CONTROL_SCREENSHOT_DIR", "data/screenshots")


SCREENSHOT_MAX_BYTES = 6 * 1024 * 1024


HOME_DIR = _env_path("CONTROL_HOME_DIR", "data/homes")


HOME_MAX_BYTES = 400 * 1024 * 1024


HOME_KEEP = 10       # copias de codigo por equipo


PHASES = ("idle", "practice", "live", "frozen", "ended")


OFFLINE_SECS = 90    # sin reportar -> offline


OFFLINE_PHASES = ("practice", "live", "frozen")


DISK_FULL_PCT = 95


STATUS_EVERY = 30   # las PCs reportan estado cada ~29s (medido en samples)


SHOT_KEEP = 20       # ultimas N por equipo


MACHINE_ID_RE = "[A-Za-z0-9._-]{1,64}"


MACHINE_ID_OK = re.compile(r"\A%s\Z" % MACHINE_ID_RE).match


# accion -> args obligatorios. Lo que no esta aqui se rechaza.
ACTIONS = {
    "lock": (),
    "unlock": (),
    "logout": (),                   # coordinador: cierra la sesion del concursante en esa maquina
    "reset-home": (),
    "message": ("text",),
    "reboot": (),
    "poweroff": (),
    "set-allowlist": ("hosts",),
    "usb-block": (),
    "usb-unblock": (),
    "set-wallpaper": ("url",),
    "set-homepage": ("url",),       # página de inicio de Firefox
    "precontest": (),
    "donottouch": (),
    "cantouch": (),
    "net-open": (),
    "net-lock": (),
    "screenshot": (),
    "collect-home": (),             # sube /home/<equipo> al control-server
    "unlock-root": ("password",),   # solo superadmin (ver _admin_cmd)
    "lock-root": (),                # solo superadmin
}


# Solo superadmin: el coordinador de sede puede bloquear pero no abrir red/USB ni sacar codigo.
SUPERADMIN_ONLY = {
    "unlock-root", "lock-root",
    "net-open", "usb-block", "usb-unblock", "collect-home", "set-allowlist",
}


# Lo unico que se entrega a una maquina congelada.
FROZEN_ALLOWED = {"cantouch", "donottouch"}


MAX_PAYLOAD_BYTES = 8192


MAX_BODY_BYTES = 262144
