from flask import Flask, render_template, request, Response, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from scapy.all import AsyncSniffer, sniff, conf, IP, TCP, UDP
import time
import os
import csv
import io
import ipaddress
import sqlite3
import socket
import json
import subprocess
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict, deque

# Importar eventlet explícitamente para que Flask-SocketIO lo detecte
try:
    import eventlet
    eventlet.monkey_patch()
    async_mode = 'eventlet'
except Exception:
    async_mode = 'threading'

app = Flask(__name__)
raw_secret_key = os.environ.get('SNIFFY_SECRET_KEY', '').strip()
if raw_secret_key:
    app.config['SECRET_KEY'] = raw_secret_key
else:
    # Evita una clave estática débil cuando no hay configuración explícita.
    app.config['SECRET_KEY'] = os.urandom(32).hex()
    print('Advertencia: SNIFFY_SECRET_KEY no configurada; usando clave efímera de arranque.')

DEFAULT_ALLOWED_ORIGINS = 'http://127.0.0.1:5000,http://localhost:5000'
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get('SNIFFY_ALLOWED_ORIGINS', DEFAULT_ALLOWED_ORIGINS).split(',')
    if origin.strip()
]
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, async_mode=async_mode)

# Almacenar estadísticas de paquetes
packet_stats = {
    'counts_per_second': defaultdict(int),
    'total_packets': 0,
    'suspicious_packets': 0,
    'regular_packets': 0,
    'safelisted_packets': 0,
    'traffic_mix': {
        'web': 0,
        'video': 0,
        'unknown': 0
    }
}
packet_log = deque(maxlen=5000)
packet_sequence = 0
sniffer_workers = []
sniffer_status = {
    'status': 'waiting',
    'message': 'Esperando inicio del sniffer...'
}

# Puertos sensibles a monitorear
SENSITIVE_PORTS = [22, 23, 445, 3389]
MAX_PACKET_SIZE = int(os.environ.get('MAX_PACKET_SIZE', '1514'))
# Lista segura configurable por CIDR. Ejemplo:
# set SAFE_IP_CIDRS=8.8.8.8/32,8.8.4.4/32,20.0.0.0/8,40.0.0.0/8
SAFE_IP_CIDRS = os.environ.get('SAFE_IP_CIDRS', '')


def parse_safe_networks(cidr_csv):
    """Parsea una lista CSV de CIDRs válidos para safelist."""
    networks = []
    if not cidr_csv.strip():
        return networks

    for raw_cidr in cidr_csv.split(','):
        cidr = raw_cidr.strip()
        if not cidr:
            continue
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            print(f'CIDR invalido en SAFE_IP_CIDRS: {cidr}')
    return networks


SAFE_NETWORKS = parse_safe_networks(SAFE_IP_CIDRS)
DB_PATH = os.path.join(os.path.dirname(__file__), 'snifflux_alerts.db')

WEB_PORTS = {80, 443, 8080, 8443}
VIDEO_PORTS = {554, 8554, 1935, 1755, 3478, 5349}
MICROSOFT_CIDRS = os.environ.get('MICROSOFT_CIDRS', '20.0.0.0/8,40.0.0.0/8,52.0.0.0/8')
MICROSOFT_NETWORKS = parse_safe_networks(MICROSOFT_CIDRS)
whois_cache = {}
country_cache = {}
CACHE_MAX_ITEMS = int(os.environ.get('SNIFFY_CACHE_MAX_ITEMS', '2000'))
rate_limit_buckets = defaultdict(deque)


def is_rate_limited(bucket_name, client_id, max_requests, window_seconds):
    """Rate limit básico en memoria por bucket + cliente."""
    key = f'{bucket_name}:{client_id}'
    now = time.time()
    bucket = rate_limit_buckets[key]
    threshold = now - window_seconds
    while bucket and bucket[0] < threshold:
        bucket.popleft()
    if len(bucket) >= max_requests:
        return True
    bucket.append(now)
    return False


def is_same_origin_request(req):
    """Permite solo requests same-origin cuando existe header Origin."""
    origin = (req.headers.get('Origin') or '').strip()
    if not origin:
        return True
    parsed = urlparse(origin)
    if not parsed.scheme or not parsed.netloc:
        return False
    return parsed.netloc == req.host


@app.after_request
def apply_security_headers(response):
    """Agrega headers defensivos para reducir superficie web."""
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' https://cdn.socket.io https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


def cache_set(cache_obj, key, value):
    """Inserta en cache con límite para evitar crecimiento indefinido."""
    cache_obj[key] = value
    if len(cache_obj) > CACHE_MAX_ITEMS:
        # Python dict mantiene orden de inserción; removemos el más antiguo.
        oldest_key = next(iter(cache_obj))
        del cache_obj[oldest_key]


def parse_bool_value(value):
    """Normaliza bool desde JSON/query params (bool, int, str)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'y', 'on'}
    return False


def init_db():
    """Inicializa base de datos SQLite para historial de alertas."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_id INTEGER,
            timestamp TEXT,
            timestamp_iso TEXT,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            length INTEGER,
            severity TEXT,
            reason TEXT,
            safelisted INTEGER,
            safelist_match TEXT,
            traffic_category TEXT,
            country TEXT,
            microsoft_related INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS block_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            ip TEXT,
            rule_name TEXT,
            command TEXT,
            status TEXT,
            output TEXT
        )
    """)
    conn.commit()
    conn.close()


def update_sniffer_status(status, message):
    """Actualiza estado del sniffer y lo emite a todos los clientes."""
    sniffer_status['status'] = status
    sniffer_status['message'] = message
    socketio.emit('sniffer_status', sniffer_status)


def parse_ip(ip_text):
    """Convierte texto a IP object o None."""
    if not ip_text or ip_text == 'N/A':
        return None
    try:
        return ipaddress.ip_address(ip_text)
    except ValueError:
        return None


def is_private_or_local(ip_text):
    """Valida si IP es local/privada para evitar lookups externos innecesarios."""
    ip_obj = parse_ip(ip_text)
    if not ip_obj:
        return True
    return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local


def classify_traffic(packet_info):
    """Clasifica trafico en web/video/unknown."""
    ports = {packet_info.get('source_port'), packet_info.get('destination_port')}
    ports.discard(None)
    if ports & WEB_PORTS:
        return 'web'
    if ports & VIDEO_PORTS:
        return 'video'
    return 'unknown'


def get_country_for_ip(ip_text):
    """Obtiene pais estimado de IP publica usando API externa con cache."""
    if is_private_or_local(ip_text):
        return 'Local/Private'
    if ip_text in country_cache:
        return country_cache[ip_text]

    url = f'https://ipwho.is/{ip_text}'
    try:
        with urlrequest.urlopen(url, timeout=2.5) as response:
            payload = json.loads(response.read().decode('utf-8', errors='ignore'))
            if payload.get('success') is True:
                country = payload.get('country', 'Unknown')
            else:
                country = 'Unknown'
    except (URLError, HTTPError, TimeoutError, OSError):
        country = 'Unknown'

    cache_set(country_cache, ip_text, country)
    return country


def get_ip_owner(ip_text):
    """Lookup WHOIS/RDAP para saber organizacion dueña de una IP."""
    if is_private_or_local(ip_text):
        return {
            'ip': ip_text,
            'owner': 'Local/Private Network',
            'asn': 'N/A',
            'country': 'Local/Private'
        }
    if ip_text in whois_cache:
        return whois_cache[ip_text]

    result = {
        'ip': ip_text,
        'owner': 'Unknown',
        'asn': 'Unknown',
        'country': get_country_for_ip(ip_text)
    }

    rdap_url = f'https://rdap.org/ip/{ip_text}'
    try:
        with urlrequest.urlopen(rdap_url, timeout=3) as response:
            payload = json.loads(response.read().decode('utf-8', errors='ignore'))
            owner = payload.get('name') or payload.get('handle') or 'Unknown'
            asn = str(payload.get('startAutnum') or payload.get('port43') or 'Unknown')
            result['owner'] = owner
            result['asn'] = asn
    except (URLError, HTTPError, TimeoutError, OSError, ValueError):
        # Fallback DNS reverse lookup
        try:
            hostname = socket.gethostbyaddr(ip_text)[0]
            result['owner'] = hostname
        except OSError:
            pass

    cache_set(whois_cache, ip_text, result)
    return result


def is_microsoft_related(packet_info):
    """Indica si source/destination coincide con rangos configurados de Microsoft."""
    if not MICROSOFT_NETWORKS:
        return False
    for field in ('source_ip', 'destination_ip'):
        ip_obj = parse_ip(packet_info.get(field))
        if not ip_obj:
            continue
        for network in MICROSOFT_NETWORKS:
            if ip_obj in network:
                return True
    return False


def get_severity_score(severity):
    """Asigna puntaje base por severidad para scoring de atacantes."""
    mapping = {
        'high': 5.0,
        'medium': 3.0,
        'low': 1.5,
        'info': 0.5
    }
    return mapping.get(str(severity).lower(), 1.0)


def save_alert_history(packet_info):
    """Persiste alertas sospechosas para analitica historica."""
    if not packet_info.get('suspicious'):
        return

    country = get_country_for_ip(packet_info.get('source_ip', ''))
    microsoft_related = 1 if is_microsoft_related(packet_info) else 0

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alert_history (
            packet_id, timestamp, timestamp_iso, source_ip, source_port,
            destination_ip, destination_port, protocol, length, severity,
            reason, safelisted, safelist_match, traffic_category, country, microsoft_related
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        packet_info.get('id'),
        packet_info.get('timestamp'),
        packet_info.get('timestamp_iso'),
        packet_info.get('source_ip'),
        packet_info.get('source_port'),
        packet_info.get('destination_ip'),
        packet_info.get('destination_port'),
        packet_info.get('protocol'),
        packet_info.get('length'),
        packet_info.get('severity'),
        packet_info.get('suspicious_reason'),
        1 if packet_info.get('safelisted') else 0,
        packet_info.get('safelist_match'),
        packet_info.get('traffic_category'),
        country,
        microsoft_related
    ))
    conn.commit()
    conn.close()


def get_safelist_match(packet_info):
    """Devuelve el CIDR de safelist que coincide con src/dst, o None."""
    if not SAFE_NETWORKS:
        return None

    for key in ('source_ip', 'destination_ip'):
        ip_raw = packet_info.get(key)
        if not ip_raw or ip_raw == 'N/A':
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_raw)
        except ValueError:
            continue
        for network in SAFE_NETWORKS:
            if ip_obj in network:
                return str(network)
    return None


def evaluate_suspicion(packet, packet_info):
    """Devuelve (is_suspicious, reason, severity)."""
    safelist_match = get_safelist_match(packet_info)
    if safelist_match:
        return (
            False,
            f'Traffic matched safe list CIDR {safelist_match}. Alert suppressed.',
            'info',
            True,
            safelist_match
        )

    reasons = []
    severity = 'low'

    if len(packet) > MAX_PACKET_SIZE:
        reasons.append(f'Packet length exceeds {MAX_PACKET_SIZE} bytes ({len(packet)}).')
        severity = 'high'

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        sensitive_ports_hit = []
        if src_port in SENSITIVE_PORTS:
            sensitive_ports_hit.append(f'source port {src_port}')
        if dst_port in SENSITIVE_PORTS:
            sensitive_ports_hit.append(f'destination port {dst_port}')
        if sensitive_ports_hit:
            reasons.append('Sensitive service detected on ' + ' and '.join(sensitive_ports_hit) + '.')
            if severity != 'high':
                severity = 'medium'

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        sensitive_ports_hit = []
        if src_port in SENSITIVE_PORTS:
            sensitive_ports_hit.append(f'source port {src_port}')
        if dst_port in SENSITIVE_PORTS:
            sensitive_ports_hit.append(f'destination port {dst_port}')
        if sensitive_ports_hit:
            reasons.append('Sensitive service detected on ' + ' and '.join(sensitive_ports_hit) + '.')
            if severity != 'high':
                severity = 'medium'

    if reasons:
        return True, ' '.join(reasons), severity, False, None
    return False, 'No suspicious indicators matched current policy.', severity, False, None


def get_candidate_interfaces():
    """Devuelve interfaces candidatas priorizadas para captura en Windows."""
    forced_iface = os.environ.get('SNIFFY_IFACE')
    if forced_iface:
        return [forced_iface]

    high_priority = []
    medium_priority = []
    low_priority = []
    seen = set()

    def add_iface(target_list, iface_name):
        if not iface_name or iface_name in seen:
            return
        seen.add(iface_name)
        target_list.append(iface_name)

    # Construir mapa para traducir network_name/GUID -> nombre amigable.
    iface_map = {}
    for guid, iface_obj in conf.ifaces.items():
        name = str(getattr(iface_obj, 'name', '')).strip()
        network_name = str(getattr(iface_obj, 'network_name', '')).strip()
        if name:
            iface_map[str(guid)] = name
            iface_map[network_name] = name

    def classify_and_add(iface_obj):
        name = str(getattr(iface_obj, 'name', '')).strip()
        if not name:
            return
        lower_name = name.lower()
        description = str(getattr(iface_obj, 'description', '')).lower()
        ip_addr = str(getattr(iface_obj, 'ip', '')).strip()

        if 'loopback' in lower_name:
            return
        if any(token in description for token in ['miniport', 'virtual adapter', 'host-only', 'wi-fi direct']):
            return
        if 'bluetooth' in description:
            return

        # Priorizamos interfaces con IP util (no APIPA ni loopback) y no virtuales.
        if ip_addr and not ip_addr.startswith('169.254.') and not ip_addr.startswith('127.'):
            add_iface(high_priority, name)
            return

        add_iface(medium_priority, name)

    # Priorizar interfaz por defecto de Scapy y la de ruta por defecto.
    default_iface_name = iface_map.get(str(conf.iface), str(conf.iface))
    add_iface(high_priority, default_iface_name)

    try:
        default_route_iface = conf.route.route('0.0.0.0')[0]
        route_iface_name = iface_map.get(str(default_route_iface), str(default_route_iface))
        add_iface(high_priority, route_iface_name)
    except Exception:
        pass

    for _, iface_obj in conf.ifaces.items():
        classify_and_add(iface_obj)

    return high_priority + medium_priority + low_priority

def extract_packet_info(packet):
    """Extrae información relevante del paquete"""
    now = datetime.now()
    info = {
        'timestamp': now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'timestamp_iso': now.isoformat(timespec='milliseconds'),
        'timestamp_unix': int(now.timestamp()),
        'source_ip': 'N/A',
        'destination_ip': 'N/A',
        'protocol': 'Unknown',
        'length': len(packet),
        'source_port': None,
        'destination_port': None,
        'suspicious': False,
        'suspicious_reason': '',
        'severity': 'low',
        'safelisted': False,
        'safelist_match': None
    }
    
    if packet.haslayer(IP):
        info['source_ip'] = packet[IP].src
        info['destination_ip'] = packet[IP].dst
        info['protocol'] = packet[IP].proto
        
        # Determinar nombre del protocolo
        if packet.haslayer(TCP):
            info['protocol'] = 'TCP'
            info['source_port'] = packet[TCP].sport
            info['destination_port'] = packet[TCP].dport
        elif packet.haslayer(UDP):
            info['protocol'] = 'UDP'
            info['source_port'] = packet[UDP].sport
            info['destination_port'] = packet[UDP].dport
        else:
            info['protocol'] = f'IP/{packet[IP].proto}'

    is_suspicious, reason, severity, safelisted, safelist_match = evaluate_suspicion(packet, info)
    info['suspicious'] = is_suspicious
    info['suspicious_reason'] = reason
    info['severity'] = severity
    info['safelisted'] = safelisted
    info['safelist_match'] = safelist_match
    info['traffic_category'] = classify_traffic(info)
    
    return info

def packet_handler(packet):
    """Maneja cada paquete capturado"""
    global packet_sequence
    try:
        if not packet.haslayer(IP):
            return

        packet_info = extract_packet_info(packet)
        packet_sequence += 1
        packet_info['id'] = packet_sequence
        current_second = int(time.time())
        packet_log.append(packet_info.copy())
        
        # Actualizar estadísticas
        packet_stats['counts_per_second'][current_second] += 1
        packet_stats['total_packets'] += 1
        packet_stats['traffic_mix'][packet_info['traffic_category']] += 1
        
        # Emitir evento según tipo de paquete
        if packet_info['safelisted']:
            packet_stats['safelisted_packets'] += 1
            socketio.emit('safelisted_packet', packet_info)
        elif packet_info['suspicious']:
            packet_stats['suspicious_packets'] += 1
            socketio.emit('suspicious_packet', packet_info)
        else:
            packet_stats['regular_packets'] += 1
            socketio.emit('regular_packet', packet_info)

        # Persistir alertas en historial SQLite
        if packet_info['suspicious']:
            save_alert_history(packet_info)
        
        # Emitir estadísticas actualizadas
        socketio.emit('packet_stats', {
            'total': packet_stats['total_packets'],
            'suspicious': packet_stats['suspicious_packets'],
            'regular': packet_stats['regular_packets'],
            'safelisted': packet_stats['safelisted_packets'],
            'current_second_count': packet_stats['counts_per_second'][current_second]
        })
        socketio.emit('traffic_mix_update', packet_stats['traffic_mix'])
        
    except Exception as e:
        print(f"Error procesando paquete: {e}")

def start_sniffer():
    """Inicia el sniffer de Scapy en un hilo separado"""
    print("Iniciando sniffer de paquetes...")
    print("NOTA: En Windows, necesitas tener Npcap o WinPcap instalado para capturar paquetes.")
    print("Si no está instalado, el sniffer no funcionará correctamente.")
    print("Descarga Npcap desde: https://nmap.org/npcap/")
    update_sniffer_status('starting', 'Iniciando captura de paquetes...')
    try:
        candidate_ifaces = get_candidate_interfaces()
        started_ifaces = []

        for iface in candidate_ifaces:
            try:
                sniffer = AsyncSniffer(
                    prn=packet_handler,
                    lfilter=lambda pkt: pkt.haslayer(IP),
                    store=False,
                    iface=iface
                )
                sniffer.start()
                sniffer_workers.append(sniffer)
                started_ifaces.append(iface)
                print(f"Sniffer activo en interfaz: {iface}")
            except Exception as iface_error:
                print(f"No se pudo iniciar captura en {iface}: {iface_error}")

        if started_ifaces:
            shown_ifaces = ', '.join(started_ifaces[:2])
            extra_count = max(0, len(started_ifaces) - 2)
            suffix = f" (+{extra_count} mas)" if extra_count else ""
            update_sniffer_status(
                'running',
                f"Capturando en {len(started_ifaces)} interfaz(es): {shown_ifaces}{suffix}"
            )

            # Mantener viva la tarea de background.
            while True:
                time.sleep(5)

        # Fallback L3 si no se pudo abrir ningun sniffer de capa 2.
        print("Intentando fallback de captura en capa 3...")
        update_sniffer_status('starting', 'Fallback L3 activo, intentando captura sin winpcap...')
        sniff(
            prn=packet_handler,
            lfilter=lambda pkt: pkt.haslayer(IP),
            store=False,
            L3socket=conf.L3socket
        )
    except OSError as e:
        print(f"Error: No se puede capturar paquetes. Asegúrate de tener Npcap instalado.")
        print(f"Detalles: {e}")
        print("El servidor continuará ejecutándose, pero no capturará tráfico de red.")
        update_sniffer_status('error', 'No se pudo iniciar captura. Instala Npcap y ejecuta como administrador.')
    except Exception as e:
        print(f"Error en el sniffer: {e}")
        update_sniffer_status('error', f'Error del sniffer: {e}')

def emit_packet_counts():
    """Emite los conteos de paquetes por segundo para el gráfico"""
    while True:
        time.sleep(1)
        current_second = int(time.time())
        count = packet_stats['counts_per_second'][current_second]
        
        # Limpiar datos antiguos (mantener solo últimos 60 segundos)
        old_second = current_second - 60
        if old_second in packet_stats['counts_per_second']:
            del packet_stats['counts_per_second'][old_second]
        
        socketio.emit('packet_count_update', {
            'timestamp': current_second,
            'count': count
        })

@app.route('/')
def index():
    """Ruta principal que sirve el HTML"""
    return render_template('index.html')


def packet_matches_filters(packet, params):
    """Aplica filtros de reporte sobre un paquete."""
    suspicious_only = params.get('suspicious_only', 'false').lower() == 'true'
    if suspicious_only and not packet['suspicious']:
        return False

    safelisted_only = params.get('safelisted_only', 'false').lower() == 'true'
    if safelisted_only and not packet.get('safelisted'):
        return False

    protocol = params.get('protocol', '').strip().upper()
    if protocol and packet['protocol'].upper() != protocol:
        return False

    severity = params.get('severity', '').strip().lower()
    if severity and packet.get('severity', '').lower() != severity:
        return False

    reason_contains = params.get('reason_contains', '').strip().lower()
    if reason_contains and reason_contains not in packet.get('suspicious_reason', '').lower():
        return False

    source_ip = params.get('source_ip', '').strip()
    if source_ip and source_ip not in packet['source_ip']:
        return False

    destination_ip = params.get('destination_ip', '').strip()
    if destination_ip and destination_ip not in packet['destination_ip']:
        return False

    min_length = params.get('min_length', '').strip()
    if min_length:
        try:
            if packet['length'] < int(min_length):
                return False
        except ValueError:
            pass

    max_length = params.get('max_length', '').strip()
    if max_length:
        try:
            if packet['length'] > int(max_length):
                return False
        except ValueError:
            pass

    start_ts = params.get('start_ts', '').strip()
    if start_ts:
        try:
            start_dt = datetime.fromisoformat(start_ts)
            packet_dt = datetime.fromisoformat(packet['timestamp_iso'])
            if packet_dt < start_dt:
                return False
        except ValueError:
            pass

    end_ts = params.get('end_ts', '').strip()
    if end_ts:
        try:
            end_dt = datetime.fromisoformat(end_ts)
            packet_dt = datetime.fromisoformat(packet['timestamp_iso'])
            if packet_dt > end_dt:
                return False
        except ValueError:
            pass

    return True


@app.route('/download-report')
def download_report():
    """Genera y descarga informe CSV con filtros opcionales."""
    filtered_packets = [pkt for pkt in packet_log if packet_matches_filters(pkt, request.args)]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'id', 'timestamp', 'timestamp_iso', 'source_ip', 'source_port',
        'destination_ip', 'destination_port', 'protocol', 'length',
        'suspicious', 'severity', 'suspicious_reason', 'safelisted',
        'safelist_match', 'timestamp_unix'
    ], extrasaction='ignore')
    writer.writeheader()
    writer.writerows(filtered_packets)

    report_name = f"sniffy_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    csv_payload = output.getvalue()
    output.close()

    return Response(
        csv_payload,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={report_name}'}
    )


@app.route('/favicon.ico')
def favicon_ico():
    """Compatibilidad de navegadores que siguen pidiendo /favicon.ico.

    Redirige al favicon servido por la carpeta static estándar de Flask.
    """
    return redirect(url_for('static', filename='img/logo.svg'))


@app.route('/api/whois')
def whois_lookup():
    """Lookup WHOIS/RDAP por IP para UI."""
    if is_rate_limited('whois', request.remote_addr or 'unknown', max_requests=30, window_seconds=60):
        return jsonify({'error': 'too many requests'}), 429
    ip_text = request.args.get('ip', '').strip()
    if not ip_text:
        return jsonify({'error': 'ip is required'}), 400
    return jsonify(get_ip_owner(ip_text))


@app.route('/api/panic-command')
def panic_command():
    """Genera comandos para bloquear IP en firewall de Windows."""
    if is_rate_limited('panic', request.remote_addr or 'unknown', max_requests=30, window_seconds=60):
        return jsonify({'error': 'too many requests'}), 429
    ip_text = request.args.get('ip', '').strip()
    if not ip_text:
        return jsonify({'error': 'ip is required'}), 400

    try:
        ipaddress.ip_address(ip_text)
    except ValueError:
        return jsonify({'error': 'invalid ip'}), 400

    rule_name = f"Snifflux_Block_{ip_text.replace(':', '_').replace('.', '_')}"
    netsh_cmd = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=in action=block remoteip={ip_text}'
    )
    powershell_cmd = (
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction Inbound -Action Block -RemoteAddress {ip_text}'
    )
    return jsonify({
        'ip': ip_text,
        'rule_name': rule_name,
        'netsh_command': netsh_cmd,
        'powershell_command': powershell_cmd
    })


@app.route('/api/auto-block', methods=['POST'])
def auto_block():
    """Bloquea una IP en firewall (opcional) con confirmación explícita."""
    if not is_same_origin_request(request):
        return jsonify({'error': 'cross-origin request denied'}), 403
    if is_rate_limited('auto_block', request.remote_addr or 'unknown', max_requests=8, window_seconds=60):
        return jsonify({'error': 'too many requests'}), 429
    payload = request.get_json(silent=True) or {}
    ip_text = str(payload.get('ip', '')).strip()
    confirmed = parse_bool_value(payload.get('confirmed', False))

    if not ip_text:
        return jsonify({'error': 'ip is required'}), 400
    if not confirmed:
        return jsonify({'error': 'confirmation required'}), 400

    try:
        ipaddress.ip_address(ip_text)
    except ValueError:
        return jsonify({'error': 'invalid ip'}), 400

    if is_private_or_local(ip_text):
        return jsonify({'error': 'refusing to block local/private ip'}), 400

    if os.name != 'nt':
        return jsonify({'error': 'auto-block is supported on Windows only'}), 400

    now = datetime.now().isoformat(timespec='seconds')
    rule_name = f"Snifflux_AutoBlock_{ip_text.replace(':', '_').replace('.', '_')}_{int(time.time())}"
    netsh_cmd = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=in action=block remoteip={ip_text}'
    )
    netsh_cmd_args = [
        'netsh',
        'advfirewall',
        'firewall',
        'add',
        'rule',
        f'name={rule_name}',
        'dir=in',
        'action=block',
        f'remoteip={ip_text}'
    ]

    # Ejecuta comando real; si no hay permisos, devuelve error util.
    try:
        completed = subprocess.run(
            netsh_cmd_args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=10
        )
        output = (completed.stdout or '') + (completed.stderr or '')
        status = 'success' if completed.returncode == 0 else 'error'
    except Exception as exc:
        status = 'error'
        output = str(exc)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO block_actions (created_at, ip, rule_name, command, status, output)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (now, ip_text, rule_name, netsh_cmd, status, output))
    conn.commit()
    conn.close()

    if status != 'success':
        return jsonify({
            'status': status,
            'ip': ip_text,
            'rule_name': rule_name,
            'command': netsh_cmd,
            'output': output.strip()
        }), 500

    return jsonify({
        'status': status,
        'ip': ip_text,
        'rule_name': rule_name,
        'command': netsh_cmd,
        'output': output.strip()
    })


@app.route('/api/alert-history')
def alert_history():
    """Entrega historial de alertas con analitica por hora y pais."""
    days = request.args.get('days', '7').strip()
    try:
        days_int = max(1, min(int(days), 60))
    except ValueError:
        days_int = 7

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM alert_history
        WHERE datetime(timestamp_iso) >= datetime('now', ?)
        ORDER BY id DESC
        LIMIT 300
    """, (f'-{days_int} days',))
    recent_rows = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT strftime('%H', timestamp_iso) AS hour, COUNT(*) AS total
        FROM alert_history
        WHERE datetime(timestamp_iso) >= datetime('now', ?)
        GROUP BY hour
        ORDER BY hour
    """, (f'-{days_int} days',))
    hourly = [{'hour': row['hour'], 'count': row['total']} for row in cursor.fetchall()]

    cursor.execute("""
        SELECT strftime('%w', timestamp_iso) AS weekday, strftime('%H', timestamp_iso) AS hour, COUNT(*) AS total
        FROM alert_history
        WHERE datetime(timestamp_iso) >= datetime('now', ?)
        GROUP BY weekday, hour
        ORDER BY weekday, hour
    """, (f'-{days_int} days',))
    heatmap = [
        {'weekday': row['weekday'], 'hour': row['hour'], 'count': row['total']}
        for row in cursor.fetchall()
    ]

    cursor.execute("""
        SELECT country, COUNT(*) AS total
        FROM alert_history
        WHERE datetime(timestamp_iso) >= datetime('now', ?)
        GROUP BY country
        ORDER BY total DESC
        LIMIT 12
    """, (f'-{days_int} days',))
    countries = [{'country': row['country'], 'count': row['total']} for row in cursor.fetchall()]

    cursor.execute("""
        SELECT country, COUNT(*) AS total
        FROM alert_history
        WHERE datetime(timestamp_iso) >= datetime('now', ?)
          AND microsoft_related = 1
        GROUP BY country
        ORDER BY total DESC
        LIMIT 12
    """, (f'-{days_int} days',))
    microsoft_countries = [{'country': row['country'], 'count': row['total']} for row in cursor.fetchall()]

    cursor.execute("""
        SELECT source_ip,
               COUNT(*) AS total_alerts,
               SUM(CASE
                    WHEN lower(severity) = 'high' THEN 5
                    WHEN lower(severity) = 'medium' THEN 3
                    WHEN lower(severity) = 'low' THEN 1.5
                    WHEN lower(severity) = 'info' THEN 0.5
                    ELSE 1
               END) AS score
        FROM alert_history
        WHERE datetime(timestamp_iso) >= datetime('now', ?)
          AND source_ip IS NOT NULL
          AND source_ip != ''
          AND source_ip != 'N/A'
        GROUP BY source_ip
        ORDER BY score DESC, total_alerts DESC
        LIMIT 15
    """, (f'-{days_int} days',))
    top_attackers = [{
        'source_ip': row['source_ip'],
        'total_alerts': row['total_alerts'],
        'score': round(float(row['score'] or 0), 2)
    } for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        'days': days_int,
        'recent_alerts': recent_rows,
        'hourly_pattern': hourly,
        'heatmap': heatmap,
        'countries': countries,
        'microsoft_countries': microsoft_countries,
        'top_attackers': top_attackers
    })


@socketio.on('connect')
def handle_connect():
    """Sincroniza estado inicial del dashboard al conectar un cliente."""
    emit('sniffer_status', sniffer_status)
    emit('packet_stats', {
        'total': packet_stats['total_packets'],
        'suspicious': packet_stats['suspicious_packets'],
        'regular': packet_stats['regular_packets'],
        'safelisted': packet_stats['safelisted_packets'],
        'current_second_count': packet_stats['counts_per_second'][int(time.time())]
    })
    emit('traffic_mix_update', packet_stats['traffic_mix'])

if __name__ == '__main__':
    init_db()
    # Iniciar el sniffer en un hilo en segundo plano
    socketio.start_background_task(start_sniffer)
    
    # Iniciar el emisor de conteos de paquetes
    socketio.start_background_task(emit_packet_counts)
    
    # Ejecutar el servidor Flask en localhost
    print("Servidor iniciando en http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)
