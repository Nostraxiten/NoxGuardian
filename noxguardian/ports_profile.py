"""Perfil de puertos por defecto para el escaneo profundo.

Se define como una lista de bloques (contiguos y sueltos) que se compacta a una
especificacion valida para `nmap -p`. La idea es cubrir:

  * todo el rango well-known (1-1024),
  * bloques densos alrededor de los rangos "vivos" en LAN domestica
    (2000, 3000, 4000, 5000, 8000, 9000, 10000...),
  * y una seleccion curada de puertos altos de alto valor (bases de datos,
    IoT, camaras, consolas, admin remota, malware clasico...).

El total ronda los 4000 puertos; `DEFAULT_PORT_COUNT` expone el numero exacto.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

# ---------------------------------------------------------------------------
# Definicion del perfil por defecto
# ---------------------------------------------------------------------------

# Bloques contiguos (inicio, fin) ambos inclusive.
_DEFAULT_RANGES: Sequence[Tuple[int, int]] = (
    (1, 1100),        # well-known completo + primer tramo registrado
    (2000, 2100),
    (3000, 3100),
    (4000, 4100),
    (5000, 5100),
    (6000, 6100),
    (7000, 7100),
    (8000, 8200),     # el rango web-alt es el mas productivo en LAN
    (9000, 9100),
    (10000, 10100),
    (11000, 11100),
    (12000, 12100),
    (13000, 13100),
    (14000, 14100),
    (15000, 15100),
    (16000, 16100),
    (17000, 17100),
    (18000, 18100),
    (19000, 19100),
    (20000, 20100),
    (21000, 21100),
    (22000, 22100),
    (23000, 23100),
    (24000, 24100),
    (25000, 25100),
    (32768, 32790),   # rango efimero clasico en routers/NAS
    (49152, 49200),   # rango efimero Windows / UPnP
    (50000, 50100),
)

# Puertos sueltos de alto valor fuera de los bloques anteriores.
_DEFAULT_SINGLES: Sequence[int] = (
    1194,   # OpenVPN
    1234, 1311,
    1337,
    1433, 1434,   # MSSQL
    1521,   # Oracle
    1604, 1701, 1720, 1723,   # Citrix, L2TP, H.323, PPTP
    1755, 1812, 1813,
    1883,   # MQTT
    1900,   # SSDP / UPnP
    1935,   # RTMP
    2121, 2181, 2222, 2323,
    2375, 2376, 2379, 2380,   # Docker / etcd
    2404,   # IEC-104
    2483, 2484, 2525,
    2601, 2604,
    3128,   # Squid
    3260,   # iSCSI
    3268, 3269, 3283,
    3306, 3307,   # MySQL
    3389, 3390,   # RDP
    3478, 3479,   # STUN/TURN
    3689, 3690,   # DAAP / svn
    3702,   # WS-Discovery
    3749, 3784, 3790,
    4242, 4243,
    4369,   # EPMD (Erlang)
    4443, 4444, 4445, 4500,
    4567, 4662, 4711, 4712, 4747,
    4840,   # OPC UA
    4848, 4899, 4900,
    5222, 5223, 5228,   # XMPP / GCM
    5269, 5280,
    5353,   # mDNS
    5357,   # WSDAPI
    5432, 5433,   # PostgreSQL
    5555, 5556,   # ADB
    5601,   # Kibana
    5631,   # pcAnywhere
    5666,   # NRPE
    5672,   # AMQP
    5683, 5684,   # CoAP
    5800, 5801, 5802, 5803, 5804, 5805,   # VNC http
    5900, 5901, 5902, 5903, 5904, 5905, 5906,   # VNC
    5938,   # TeamViewer
    5984,   # CouchDB
    5985, 5986,   # WinRM
    6379,   # Redis
    6443,   # Kubernetes API
    6446, 6543, 6600, 6633,
    6666, 6667, 6668, 6669, 6697,   # IRC
    6881,   # BitTorrent
    6969,
    7170, 7443, 7474,
    7547,   # TR-069 (routers ISP)
    7777, 7778, 7860, 7861,
    8222, 8243, 8280, 8291,   # 8291 = Mikrotik Winbox
    8333, 8383, 8400,
    8443, 8444, 8500, 8554,   # 8554 = RTSP alt (camaras)
    8649, 8686, 8765, 8787, 8800, 8834,
    8880, 8883,   # MQTT/TLS
    8888, 8889, 8899, 8983,
    9160, 9200, 9300,   # Cassandra / Elasticsearch
    9418,   # git
    9443, 9500, 9535, 9595, 9600, 9700, 9800,
    9876, 9877, 9878, 9898, 9900, 9943, 9944, 9981, 9999,
    10243, 10250, 10255, 10443, 10554, 10809, 10911,
    11211,  # memcached
    11371, 11967,
    12345, 12346, 12443, 12489,
    13720, 13722, 13782, 13783,
    16992, 16993,   # Intel AMT
    27017, 27018, 27019,   # MongoDB
    28017,
    31337,
    32764,  # backdoor routers SerComm
    33060,  # MySQL X
    34567,  # DVR chinos
    37777,  # Dahua DVR
    41794, 41795,
    44158, 44818,
    47808, 47809,   # BACnet
    51820,  # WireGuard
    52869,  # UPnP Realtek (exploit clasico)
    54321,
    55553, 55554,   # Metasploit
    62078,  # iPhone lockdownd
    64738,  # Mumble
)


# ---------------------------------------------------------------------------
# Utilidades de expansion / compactacion de especificaciones de puertos
# ---------------------------------------------------------------------------


def compact(ports: Iterable[int]) -> str:
    """Convierte un iterable de puertos en una spec compacta tipo `1-1024,8080`."""
    unique = sorted({int(p) for p in ports})
    if not unique:
        return ""
    chunks: List[str] = []
    start = prev = unique[0]
    for port in unique[1:]:
        if port == prev + 1:
            prev = port
            continue
        chunks.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = port
    chunks.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(chunks)


def expand(spec: str) -> List[int]:
    """Expande una spec tipo `1-1024,8080,9000-9100` a una lista de puertos.

    Lanza ValueError si la spec es invalida o contiene puertos fuera de 1-65535.
    """
    ports: set[int] = set()
    for raw in spec.split(","):
        token = raw.strip()
        if not token:
            continue
        if "-" in token:
            lo_s, _, hi_s = token.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError as exc:
                raise ValueError(f"rango de puertos invalido: '{token}'") from exc
            if lo > hi:
                lo, hi = hi, lo
            if lo < 1 or hi > 65535:
                raise ValueError(f"rango fuera de 1-65535: '{token}'")
            ports.update(range(lo, hi + 1))
        else:
            try:
                port = int(token)
            except ValueError as exc:
                raise ValueError(f"puerto invalido: '{token}'") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"puerto fuera de 1-65535: '{token}'")
            ports.add(port)
    if not ports:
        raise ValueError("la especificacion de puertos esta vacia")
    return sorted(ports)


def normalize(spec: str) -> str:
    """Valida y re-compacta una spec proporcionada por el usuario."""
    return compact(expand(spec))


def count(spec: str) -> int:
    """Numero de puertos que cubre una spec."""
    return len(expand(spec))


def _build_default() -> str:
    ports: set[int] = set(_DEFAULT_SINGLES)
    for lo, hi in _DEFAULT_RANGES:
        ports.update(range(lo, hi + 1))
    return compact(ports)


DEFAULT_PORT_SPEC: str = _build_default()
DEFAULT_PORT_COUNT: int = count(DEFAULT_PORT_SPEC)


if __name__ == "__main__":  # pragma: no cover - inspeccion manual
    print(f"puertos: {DEFAULT_PORT_COUNT}")
    print(DEFAULT_PORT_SPEC)
