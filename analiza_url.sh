#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ANALIZADOR DE SISTEMAS Y URLS - Versión para Ubuntu/Linux
# Creado por Quien sabe?
# --- Versión con Análisis Completo de URL Única (Gemini) ---

import argparse
import re
import socket
import subprocess
import sys
import time
import importlib.util
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# --- Colores para la terminal ---
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- PARÁMETROS DE CONFIGURACIÓN FÁCIL ---
URL_TIMEOUT = 5
LARGE_LIST_THRESHOLD = 2000
NORMAL_WORKERS = 15
LARGE_LIST_WORKERS = 30
PANEL_SCAN_WORKERS = 25

# --- Verificación e instalación de dependencias ---
def check_and_install_dependencies():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Colors.WARNING}Advertencia: 'pip' no está instalado. Intentando instalarlo con 'sudo apt'.{Colors.ENDC}")
        try:
            subprocess.check_call(['sudo', 'apt', 'update'])
            subprocess.check_call(['sudo', 'apt', 'install', 'python3-pip', '-y'])
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.FAIL}Error: No se pudo instalar 'python3-pip'. Por favor, instálalo manualmente.{Colors.ENDC}"); sys.exit(1)

    required_packages = {
        'requests': 'requests',
        'tqdm': 'tqdm',
        'dnspython': 'dns.resolver',
        'OpenSSL': 'OpenSSL',
        'cryptography': 'cryptography'
    }
    missing_packages = [pkg for pkg, imp_path in required_packages.items() if importlib.util.find_spec(imp_path) is None]

    if missing_packages:
        print(f"{Colors.WARNING}Advertencia: Faltan dependencias: {', '.join(missing_packages)}{Colors.ENDC}")
        try:
            if any(p in missing_packages for p in ['OpenSSL', 'cryptography']):
                    print("Instalando dependencias de sistema para criptografía (puede pedir contraseña)...")
                    subprocess.check_call(['sudo', 'apt', 'install', 'build-essential', 'libssl-dev', 'libffi-dev', 'python3-dev', '-y'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages])
            print(f"{Colors.OKGREEN}✅ Dependencias instaladas correctamente.{Colors.ENDC}")
            global dns, OpenSSL
            import dns.resolver
            import OpenSSL
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"{Colors.FAIL}Error al instalar dependencias. Por favor, ejecute 'pip3 install {' '.join(missing_packages)}'{Colors.ENDC}"); sys.exit(1)

check_and_install_dependencies()

import requests
import dns.resolver
import OpenSSL
from tqdm import tqdm

analysis_cache = {
    "is_analyzed": False,
    "ip_to_domains": {},
    "ip_details_cache": {},
    "ip_to_urls": {},
    "source_url": None,
    "timeouts": 0
}

def reset_cache():
    """Limpia la caché para permitir un nuevo análisis de lista."""
    global analysis_cache
    analysis_cache = {
        "is_analyzed": False,
        "ip_to_domains": {},
        "ip_details_cache": {},
        "ip_to_urls": {},
        "source_url": None,
        "timeouts": 0
    }
    print(f"\n{Colors.OKBLUE}Caché de análisis limpiada. Listo para una nueva lista.{Colors.ENDC}")

analysis_interrupted = False

# --- Bloque de funciones de obtención de datos ---
def get_ip_for_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}
        response = requests.get(url, timeout=URL_TIMEOUT, headers=headers, stream=True, allow_redirects=True)
        final_domain = urlparse(response.url).hostname
        if final_domain: return socket.gethostbyname(final_domain)
    except requests.exceptions.Timeout: return "timeout"
    except Exception:
        try:
            domain = urlparse(url).hostname
            if domain: return socket.gethostbyname(domain)
        except Exception: return None
    return None

def get_ip_details(ip, cache):
    if ip in cache: return cache[ip]
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        if response.status_code == 200:
            data = response.json(); details = {'country': data.get('country', 'N/A'), 'isp': data.get('org', 'N/A')}
            cache[ip] = details; return details
    except requests.RequestException: pass
    return None

def parse_m3u(content):
    channels = []; lines = content.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith('#EXTINF') and i + 1 < len(lines):
            channel_name = line.split(',')[-1].strip()
            next_line = lines[i+1].strip()
            if next_line and not next_line.startswith('#'):
                channels.append({'name': channel_name, 'url': next_line})
    return channels

# --- Bloque de funciones de análisis ---
def find_origin_ip_advanced(domain, cloudflare_ips):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(f"https://sitecheck.sucuri.net/results/{domain}", headers=headers, timeout=15)
        match = re.search(r'Host Server IP:<\/strong>\s*<a href="[^"]+">([\d\.]+)<\/a>', response.text)
        if match:
            ip = match.group(1)
            if ip not in cloudflare_ips: return ip, "Fuga por Escáner (Sucuri)"
    except requests.RequestException: pass
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for record in sorted(mx_records, key=lambda r: r.preference):
            mail_server = str(record.exchange).rstrip('.'); ip = socket.gethostbyname(mail_server)
            if ip not in cloudflare_ips: return ip, "Fuga de Correo (MX)"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, socket.error): pass
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if response.status_code == 200:
            subdomains = set(cert['name_value'] for cert in response.json())
            for sub in subdomains:
                if '*' not in sub:
                    try:
                        ip = socket.gethostbyname(sub)
                        if ip not in cloudflare_ips: return ip, f"Certificado SSL ({sub})"
                    except socket.error: continue
    except requests.RequestException: pass
    common_subdomains = ["ftp", "cpanel", "webmail", "mail", "direct", "dev", "test", "d.","m.","api."]
    for sub in common_subdomains:
        lookup = f"{sub}{domain}" if sub.endswith('.') else f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(lookup)
            if ip not in cloudflare_ips: return ip, f"Subdominio ({lookup})"
        except socket.error: continue
    return None, None

def scan_port(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout): return True
    except (socket.timeout, ConnectionRefusedError, OSError): return False

def find_web_panel(ip):
    PANEL_PORTS = {"Xtream UI / XUI": [25500, 25461, 8000, 8080], "Panel IPTV Genérico": [8880, 8888], "cPanel": [2083, 2082], "Plesk": [8443], "DirectAdmin": [2222]}
    for panel, ports in PANEL_PORTS.items():
        for port in ports:
            if scan_port(ip, port, 1.5): return f"{Colors.OKGREEN}✔️ {panel} ({port}){Colors.ENDC}"
    return f"{Colors.FAIL}✖️ No detectado{Colors.ENDC}"

# --- Funciones de Utilidad de Informes ---
def print_report_to_console(title, report_lines):
    print("\n" + "="*120); print(f"{Colors.BOLD}{title.center(120)}{Colors.ENDC}"); print("="*120)
    for line in report_lines: print(line)

def save_report_to_file(title, report_lines, output_file):
    report_content = f"{title.center(120)}\n{'='*120}\n\n"
    for line in report_lines: report_content += re.sub(r'\033\[\d+m', '', line) + "\n"
    try:
        with open(output_file, 'w', encoding='utf-8') as f: f.write(report_content)
        print(f"\n{Colors.OKGREEN}✅ Informe guardado en: {output_file}{Colors.ENDC}")
    except IOError as e: print(f"\n{Colors.FAIL}Error al guardar el informe: {e}{Colors.ENDC}")

# --- INICIO DE BLOQUE NUEVO: ANÁLISIS COMPLETO DE URL ÚNICA ---
def full_single_url_analysis():
    """
    Realiza un análisis completo y exhaustivo de una única URL, incluyendo búsqueda
    de origen de Cloudflare y escaneo de paneles.
    """
    target_url = input(f"\n{Colors.OKCYAN}{Colors.BOLD}Introduce la URL a analizar por completo: {Colors.ENDC}")
    if not target_url:
        print(f"{Colors.FAIL}No se ha introducido una URL.{Colors.ENDC}")
        return

    # Validar y limpiar la URL
    parsed_url = urlparse(target_url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        print(f"{Colors.FAIL}La URL '{target_url}' no es válida. Asegúrate de que incluya http:// o https://{Colors.ENDC}")
        return
    
    target_domain = parsed_url.netloc
    report_lines = []
    title = f"INFORME DE ANÁLISIS COMPLETO PARA {target_domain}"
    print(f"\n{Colors.HEADER}--- Iniciando análisis completo de {target_domain} ---{Colors.ENDC}")

    ip_details_cache = {}
    ip_to_scan = None
    
    # 1. Resolución de IP inicial
    try:
        print("1. Obteniendo información de la IP inicial...")
        initial_ip = socket.gethostbyname(target_domain)
        initial_details = get_ip_details(initial_ip, ip_details_cache)
        isp = initial_details.get('isp', 'N/A')
        country = initial_details.get('country', 'N/A')
        
        report_lines.append(f"{Colors.OKCYAN}--- Información del Dominio ---{Colors.ENDC}")
        report_lines.append(f"  - {Colors.BOLD}Dominio Analizado:{Colors.ENDC} {target_domain}")
        report_lines.append(f"  - {Colors.BOLD}IP Resuelta (Inicial):{Colors.ENDC} {initial_ip}")
        report_lines.append(f"  - {Colors.BOLD}ISP (Inicial):{Colors.ENDC} {isp} ({country})")
        
        ip_to_scan = initial_ip

        # 2. Detección de Cloudflare y búsqueda de origen
        if 'cloudflare' in isp.lower():
            report_lines.append(f"\n{Colors.WARNING}--- Detección de Cloudflare ---{Colors.ENDC}")
            report_lines.append("  - El dominio parece estar protegido por Cloudflare.")
            print("2. Cloudflare detectado. Buscando IP de origen real...")
            
            origin_ip, method = find_origin_ip_advanced(target_domain, {initial_ip})
            
            if origin_ip:
                origin_details = get_ip_details(origin_ip, ip_details_cache)
                report_lines.append(f"  - {Colors.OKGREEN}{Colors.BOLD}¡IP de Origen Encontrada!{Colors.ENDC}")
                report_lines.append(f"    └─ {Colors.BOLD}IP Real:{Colors.ENDC} {origin_ip}")
                report_lines.append(f"    └─ {Colors.BOLD}ISP Real:{Colors.ENDC} {origin_details.get('isp', 'N/A')} ({origin_details.get('country', 'N/A')})")
                report_lines.append(f"    └─ {Colors.BOLD}Método:{Colors.ENDC} {method}")
                ip_to_scan = origin_ip # Usaremos la IP real para el escaneo de panel
            else:
                report_lines.append(f"  - {Colors.FAIL}{Colors.BOLD}No se pudo encontrar la IP de origen.{Colors.ENDC} El escaneo de panel se realizará en la IP de Cloudflare.")
        else:
             print("2. El dominio no parece usar Cloudflare.")

    except socket.gaierror:
        print(f"{Colors.FAIL}Error fatal: No se pudo resolver el dominio '{target_domain}'.{Colors.ENDC}")
        return
    
    # 3. Escaneo de paneles
    if ip_to_scan:
        print(f"3. Buscando paneles web en la IP final ({ip_to_scan})...")
        panel_info = find_web_panel(ip_to_scan)
        report_lines.append(f"\n{Colors.OKCYAN}--- Escaneo de Panel de Administración ---{Colors.ENDC}")
        report_lines.append(f"  - {Colors.BOLD}IP Escaneada:{Colors.ENDC} {ip_to_scan}")
        report_lines.append(f"  - {Colors.BOLD}Resultado:{Colors.ENDC} {panel_info}")
    
    # 4. Mostrar informe final
    print_report_to_console(title, report_lines)
    output_file = get_output_filename()
    if output_file:
        save_report_to_file(title, report_lines, output_file)

# --- FIN DE BLOQUE NUEVO ---


# --- Herramientas Principales del Menú ---
def measure_latency():
    target = input(f"\n{Colors.OKCYAN}{Colors.BOLD}Introduce el Dominio o IP a diagnosticar (ej: google.com): {Colors.ENDC}")
    if not target: print(f"{Colors.FAIL}No se ha introducido un objetivo.{Colors.ENDC}"); return
    try:
        duration_str = input(f"{Colors.OKCYAN}{Colors.BOLD}Introduce la duración del análisis en segundos (ej: 30): {Colors.ENDC}")
        duration_seconds = int(duration_str)
    except ValueError: print(f"{Colors.FAIL}Duración no válida. Debe ser un número.{Colors.ENDC}"); return
    print(f"\n{Colors.OKCYAN}--- Realizando diagnóstico de {target} ---{Colors.ENDC}")
    preliminary_report = []; ip_details_cache = {}
    try:
        ip = socket.gethostbyname(target)
        details = get_ip_details(ip, ip_details_cache)
        isp = details.get('isp', 'N/A'); country = details.get('country', 'N/A')
        preliminary_report.append(f"  {Colors.BOLD}IP Resuelta:{Colors.ENDC} {ip}")
        preliminary_report.append(f"  {Colors.BOLD}ISP:{Colors.ENDC} {isp} ({country})")
        ip_to_ping = ip
        if 'cloudflare' in isp.lower():
            preliminary_report.append(f"  {Colors.WARNING}Detectado Cloudflare. Buscando IP de origen...{Colors.ENDC}")
            origin_ip, method = find_origin_ip_advanced(target, {ip})
            if origin_ip:
                origin_details = get_ip_details(origin_ip, ip_details_cache)
                preliminary_report.append(f"  {Colors.OKGREEN}IP de Origen Encontrada:{Colors.ENDC} {origin_ip} (ISP: {origin_details.get('isp', 'N/A')})")
                preliminary_report.append(f"    {Colors.OKCYAN}└─ Método:{Colors.ENDC} {method}"); ip_to_ping = origin_ip
            else: preliminary_report.append(f"  {Colors.FAIL}No se pudo encontrar la IP de origen.{Colors.ENDC}")
        panel_info = find_web_panel(ip_to_ping)
        preliminary_report.append(f"  {Colors.BOLD}Panel Detectado:{Colors.ENDC} {panel_info}")
    except socket.gaierror: print(f"{Colors.FAIL}Error: No se pudo resolver el dominio '{target}'.{Colors.ENDC}"); return
    for line in preliminary_report: print(line)
    print(f"\n{Colors.OKCYAN}--- Iniciando ping de {duration_seconds}s a {target} ({ip_to_ping}) ---{Colors.ENDC}")
    ping_results = []; packets_sent = 0; start_time = time.time()
    try:
        while time.time() - start_time < duration_seconds:
            packets_sent += 1
            try:
                command = ['ping', '-c', '1', '-W', '2', ip_to_ping]
                output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
                match = re.search(r'time=([\d\.]+) ms', output)
                if match:
                    latency = float(match.group(1)); ping_results.append(latency)
                    color = Colors.OKGREEN
                    if latency > 150: color = Colors.FAIL
                    elif latency > 80: color = Colors.WARNING
                    print(f"Respuesta desde {ip_to_ping}: seq={packets_sent-1} tiempo={color}{latency:.2f} ms{Colors.ENDC}")
                else:
                    ping_results.append(None); print(f"{Colors.FAIL}Respuesta extraña desde {ip_to_ping} (seq={packets_sent-1}).{Colors.ENDC}")
            except subprocess.CalledProcessError:
                ping_results.append(None); print(f"{Colors.FAIL}Fallo de ping a {ip_to_ping}: seq={packets_sent-1} Sin respuesta.{Colors.ENDC}")
            time_left = duration_seconds - (time.time() - start_time)
            if time_left > 1: time.sleep(1)
    except KeyboardInterrupt: print(f"\n\n{Colors.OKBLUE}--- Ping detenido por el usuario ---{Colors.ENDC}")
    print(f"\n{Colors.OKCYAN}--- Análisis de latencia finalizado ---{Colors.ENDC}")
    successful_pings = [p for p in ping_results if p is not None]; packets_received = len(successful_pings)
    packet_loss = ((packets_sent - packets_received) / packets_sent * 100) if packets_sent > 0 else 0
    report_lines = []; report_lines.extend(preliminary_report); report_lines.append("\n" + "="*40); report_lines.append("Estadísticas de Ping:"); report_lines.append("="*40)
    report_lines.append(f"  Paquetes: Enviados = {packets_sent}, Recibidos = {packets_received}, Perdidos = {packets_sent - packets_received} ({packet_loss:.1f}% pérdida)")
    if successful_pings:
        min_latency = min(successful_pings); max_latency = max(successful_pings); avg_latency = sum(successful_pings) / len(successful_pings)
        report_lines.append("Tiempos de ida y vuelta aproximados en milisegundos:")
        report_lines.append(f"  Mínimo = {min_latency:.2f}ms, Máximo = {max_latency:.2f}ms, Media = {avg_latency:.2f}ms")
    title = f"INFORME DE DIAGNÓSTICO Y LATENCIA PARA {target}"
    print_report_to_console(title, report_lines)
    output_file = get_output_filename()
    if output_file: save_report_to_file(title, report_lines, output_file)

def analyze_server_fast():
    target = input(f"\n{Colors.OKCYAN}{Colors.BOLD}Introduce el Dominio o IP a analizar: {Colors.ENDC}")
    if not target: print(f"{Colors.FAIL}No se ha introducido un objetivo.{Colors.ENDC}"); return
    report_lines = []
    print(f"\n{Colors.OKCYAN}--- Realizando análisis rápido de {target} ---{Colors.ENDC}")
    try:
        ip = socket.gethostbyname(target)
        report_lines.append(f"  {Colors.BOLD}IP Resuelta:{Colors.ENDC} {ip}")
    except socket.gaierror: print(f"{Colors.FAIL}Error: No se pudo resolver el dominio '{target}'.{Colors.ENDC}"); return
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(f"http://{target}", headers=headers, timeout=5)
        report_lines.append(f"\n  {Colors.BOLD}⚙️  Cabeceras HTTP:{Colors.ENDC}")
        report_lines.append(f"    - Server: {response.headers.get('Server', 'No encontrado')}")
        report_lines.append(f"    - X-Powered-By: {response.headers.get('X-Powered-By', 'No encontrado')}")
        if 'wp-content' in response.text: report_lines.append(f"    - {Colors.OKGREEN}Tecnología Detectada: WordPress{Colors.ENDC}")
        elif 'Joomla!' in response.text: report_lines.append(f"    - {Colors.OKGREEN}Tecnología Detectada: Joomla!{Colors.ENDC}")
    except requests.RequestException: report_lines.append(f"  {Colors.FAIL}No se pudo conectar al puerto 80 (HTTP).{Colors.ENDC}")
    try:
        cert = socket.getaddrinfo(target, 443, proto=socket.IPPROTO_TCP)
        stream = socket.create_connection(cert[0][4], timeout=5)
        crypto_conn = OpenSSL.SSL.Connection(OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD), stream)
        crypto_conn.set_tlsext_host_name(target.encode()); crypto_conn.set_connect_state(); crypto_conn.do_handshake()
        x509 = crypto_conn.get_peer_certificate(); crypto_conn.close()
        report_lines.append(f"\n  {Colors.BOLD}🔒 Detalles del Certificado SSL:{Colors.ENDC}")
        report_lines.append(f"    - Emisor: {dict(x509.get_issuer().get_components()).get(b'O', b'N/A').decode()}")
        exp_date = time.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        report_lines.append(f"    - Válido hasta: {time.strftime('%Y-%m-%d', exp_date)}")
        sans = []
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()): sans.extend([s.strip() for s in str(ext).split(',')])
        if sans: report_lines.append(f"    - Dominios Alternativos: {', '.join(sans)}")
    except Exception: report_lines.append(f"\n  {Colors.FAIL}No se pudo obtener información del certificado SSL (puerto 443).{Colors.ENDC}")
    try:
        report_lines.append(f"\n  {Colors.BOLD}💡 Registros DNS Clave:{Colors.ENDC}")
        mx_records = dns.resolver.resolve(target, 'MX')
        mx_servers = sorted([str(r.exchange).rstrip('.') for r in mx_records])
        report_lines.append(f"    - Servidores de Correo (MX): {', '.join(mx_servers)}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN): report_lines.append(f"    - Servidores de Correo (MX): No encontrados")
    title = f"INFORME RÁPIDO DE SERVIDOR PARA {target}"
    print_report_to_console(title, report_lines)
    output_file = get_output_filename()
    if output_file: save_report_to_file(title, report_lines, output_file)

def display_conversion_submenu():
    """Muestra el submenú para la herramienta de conversión de URL."""
    print("\n" + "="*80)
    print(f"{Colors.BOLD}{'MENÚ DE CONVERSIÓN DE URL'.center(80)}{Colors.ENDC}")
    print("="*80)
    print(f"  {Colors.OKCYAN}1){Colors.ENDC} Convertir desde URL completa de stream (.../live/user/pass/...)\n"
          f"  {Colors.OKCYAN}2){Colors.ENDC} Construir URL desde datos (DNS, Usuario, Contraseña)\n\n"
          f"  {Colors.WARNING}3){Colors.ENDC} Volver al menú principal")
    while True:
        choice = input(f"\n{Colors.OKCYAN}{Colors.BOLD}Elige una opción (1-3): {Colors.ENDC}")
        if choice in ['1', '2', '3']:
            return choice
        print(f"{Colors.FAIL}Opción no válida. Por favor, introduce un número del 1 al 3.{Colors.ENDC}")

def convert_from_full_url():
    """Toma una URL de un solo canal y la convierte en una URL de lista M3U completa."""
    print(f"\n{Colors.HEADER}--- Convertir desde URL Completa ---{Colors.ENDC}")
    stream_url = input(f"{Colors.OKCYAN}Introduce la URL del stream a convertir: {Colors.ENDC}")
    if not stream_url.strip():
        print(f"{Colors.FAIL}No se introdujo ninguna URL.{Colors.ENDC}")
        return

    match = re.search(r'^(?P<server>https?://[^/]+)/live/(?P<user>[^/]+)/(?P<pass>[^/]+)(/.*)?$', stream_url)
    
    if match:
        data = match.groupdict()
        server = data['server']
        user = data['user']
        password = data['pass']
        list_url = f"{server}/get.php?username={user}&password={password}&type=m3u_plus&output=ts"
        
        print(f"\n{Colors.OKGREEN}¡Conversión Exitosa!{Colors.ENDC}")
        print("-" * 40)
        print(f"{Colors.BOLD}URL de la lista M3U generada:{Colors.ENDC}")
        print(f"{Colors.OKBLUE}{list_url}{Colors.ENDC}")
        print("-" * 40)
        print("\nAhora puedes copiar esta URL y usarla en la 'Opción 1' para analizar la lista completa.")
    else:
        print(f"\n{Colors.FAIL}Error: El formato de la URL no es válido.{Colors.ENDC}")
        print("El formato esperado es: http://dominio:puerto/live/USUARIO/CONTRASEÑA/...")

def build_url_from_data():
    """Construye una URL de lista M3U a partir de datos introducidos por el usuario."""
    print(f"\n{Colors.HEADER}--- Construir URL desde Datos ---{Colors.ENDC}")
    host = input(f"{Colors.OKCYAN}Introduce la DNS/Host y Puerto (ej: http://dominio.com:8080): {Colors.ENDC}").strip()
    user = input(f"{Colors.OKCYAN}Introduce el Usuario: {Colors.ENDC}").strip()
    password = input(f"{Colors.OKCYAN}Introduce la Contraseña: {Colors.ENDC}").strip()

    if not all([host, user, password]):
        print(f"{Colors.FAIL}Error: Todos los campos (Host, Usuario, Contraseña) son obligatorios.{Colors.ENDC}")
        return
        
    if not host.startswith(('http://', 'https://')):
        host = 'http://' + host
        print(f"{Colors.WARNING}Se ha añadido 'http://' al host. Resultado: {host}{Colors.ENDC}")

    list_url = f"{host}/get.php?username={user}&password={password}&type=m3u_plus&output=ts"
    
    print(f"\n{Colors.OKGREEN}¡URL Construida con Éxito!{Colors.ENDC}")
    print("-" * 40)
    print(f"{Colors.BOLD}URL de la lista M3U generada:{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{list_url}{Colors.ENDC}")
    print("-" * 40)
    print("\nAhora puedes copiar esta URL y usarla en la 'Opción 1' para analizar la lista completa.")

def handle_url_conversion():
    """Función principal que gestiona el submenú de conversión de URL."""
    while True:
        choice = display_conversion_submenu()
        if choice == '1':
            convert_from_full_url()
        elif choice == '2':
            build_url_from_data()
        elif choice == '3':
            break
        
        input(f"\n{Colors.OKBLUE}Presiona Enter para volver al menú de conversión...{Colors.ENDC}")

def run_list_analysis(content, source_url=None):
    """
    Procesa cualquier contenido de texto, extrayendo URLs vía regex y M3U.
    Añade la URL de origen al principio de la lista para su análisis prioritario.
    """
    global analysis_interrupted
    analysis_interrupted = False
    timeouts_count = 0
    
    print(f"\n{Colors.HEADER}--- Iniciando Reconocimiento Universal de URLs y Dominios ---{Colors.ENDC}")
    
    items_to_process = parse_m3u(content)
    processed_urls = {item['url'] for item in items_to_process}
    all_raw_urls = sorted(list(set(re.findall(r'https?://[^\s"\'<>]+', content))))
    for url in all_raw_urls:
        if url not in processed_urls:
            items_to_process.append({'url': url})

    if source_url:
        print(f"{Colors.OKCYAN}ℹ️  Asegurando que la URL de origen ({source_url}) esté en el análisis...{Colors.ENDC}")
        if not any(item['url'] == source_url for item in items_to_process):
            items_to_process.insert(0, {'name': 'URL DE ORIGEN DE LA LISTA', 'url': source_url})

    if not items_to_process:
        print(f"{Colors.FAIL}Error: No se encontraron URLs o elementos válidos para analizar.{Colors.ENDC}")
        return None, None, None, 0

    print(f"🔎 Encontrados {len(items_to_process)} elementos únicos. Obteniendo IPs...")
    workers = LARGE_LIST_WORKERS if len(items_to_process) > LARGE_LIST_THRESHOLD else NORMAL_WORKERS
    
    ip_to_domains = {}
    ip_to_urls = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_item = {executor.submit(get_ip_for_url, item['url']): item for item in items_to_process}
        for future in tqdm(as_completed(future_to_item), total=len(items_to_process), desc="Procesando URLs"):
            item = future_to_item[future]
            try:
                ip_or_status = future.result()
                if ip_or_status == "timeout":
                    timeouts_count += 1
                elif ip_or_status:
                    domain = urlparse(item['url']).hostname
                    if ip_or_status not in ip_to_domains:
                        ip_to_domains[ip_or_status] = set()
                    ip_to_domains[ip_or_status].add(domain)

                    if ip_or_status not in ip_to_urls:
                        ip_to_urls[ip_or_status] = []
                    ip_to_urls[ip_or_status].append(item)
            except Exception:
                pass

    unique_ips = set(ip_to_domains.keys())
    ip_details_cache = {}
    print(f"\n📊 Obteniendo detalles para {len(unique_ips)} IPs únicas...")
    for ip in tqdm(unique_ips, desc="Obteniendo Detalles IP"):
        get_ip_details(ip, ip_details_cache)
    
    return ip_to_domains, ip_details_cache, ip_to_urls, timeouts_count

def generate_grouped_report(ip_to_domains, ip_details_cache, ip_to_urls, source_url=None):
    title = "INFORME BÁSICO AGRUPADO POR ISP Y DOMINIO"; report_lines = []; report_data = {}
    for ip, domains in ip_to_domains.items():
        isp = ip_details_cache.get(ip, {}).get('isp', 'Desconocido')
        if isp not in report_data: report_data[isp] = {}
        for domain in domains:
            if domain not in report_data[isp]: report_data[isp][domain] = set()
            report_data[isp][domain].add(ip)
    for isp, domains_data in sorted(report_data.items()):
        report_lines.append(f"\n{Colors.OKCYAN}🏢 ISP: {isp}{Colors.ENDC}")
        for domain, ips in sorted(domains_data.items()):
            domain_url_count = sum(len(ip_to_urls.get(ip, [])) for ip in ips)
            url_count_str = f"({domain_url_count} URLs en total)"
            report_lines.append(f"  └─ {Colors.BOLD}Dominio:{Colors.ENDC} {domain} {url_count_str}")
            for ip in sorted(list(ips)):
                country = ip_details_cache.get(ip, {}).get('country', 'N/A')
                ip_url_count = len(ip_to_urls.get(ip, [])) 
                ip_url_count_str = f"({ip_url_count} URLs)"
                report_lines.append(f"     - {Colors.BOLD}IP:{Colors.ENDC} {ip.ljust(16)} {ip_url_count_str.ljust(12)} ({country})")
    print_report_to_console(title, report_lines); output_file = get_output_filename();
    if output_file: save_report_to_file(title, report_lines, output_file)
    
def generate_channel_report(ip_to_domains, ip_details_cache, ip_to_urls, source_url=None):
    title = "INFORME DE CANALES AGRUPADO POR ISP Y DOMINIO"; report_lines = []; report_data = {}
    for ip, items in ip_to_urls.items():
        isp = ip_details_cache.get(ip, {}).get('isp', 'Desconocido')
        if isp not in report_data: report_data[isp] = {}
        domains_in_ip = {}
        for item in items:
            domain = urlparse(item['url']).hostname
            if domain not in domains_in_ip: domains_in_ip[domain] = []
            if 'name' in item: domains_in_ip[domain].append(item['name'])
        for domain, channels in domains_in_ip.items():
            if domain not in report_data[isp]:
                report_data[isp][domain] = {'channels': [], 'ip': ip, 'url_count': 0}
            report_data[isp][domain]['channels'].extend(channels)
            report_data[isp][domain]['url_count'] = len([i for i in ip_to_urls.get(ip, []) if urlparse(i['url']).hostname == domain])
    for isp, domains_data in sorted(report_data.items()):
        report_lines.append(f"\n{Colors.OKCYAN}🏢 ISP: {isp}{Colors.ENDC}")
        for domain, data in sorted(domains_data.items()):
            country = ip_details_cache.get(data['ip'], {}).get('country', 'N/A')
            unique_channels = sorted(list(set(data['channels'])))
            url_count_str = f"({data['url_count']} URLs)"
            ip_str = f"{Colors.HEADER}{Colors.BOLD}{data['ip']}{Colors.ENDC}"
            report_lines.append(f"  └─ {Colors.BOLD}Dominio:{Colors.ENDC} {domain.ljust(25)} {url_count_str.ljust(12)} | {Colors.BOLD}IP:{Colors.ENDC} {ip_str.ljust(30)} | {Colors.BOLD}Canales:{Colors.ENDC} {len(unique_channels)}")
            num_columns = 4; column_width = 30 
            for i in range(0, len(unique_channels), num_columns):
                chunk = unique_channels[i:i + num_columns]
                row_items = [f"  📺 {name:.{column_width-5}}..." if len(name) > column_width-4 else f"  📺 {name}" for name in chunk]
                while len(row_items) < num_columns: row_items.append("")
                line = "".join(item.ljust(column_width) for item in row_items)
                report_lines.append(line)
    print_report_to_console(title, report_lines); output_file = get_output_filename();
    if output_file: save_report_to_file(title, report_lines, output_file)

def generate_panel_report(ip_to_domains, ip_details_cache, ip_to_urls, source_url=None):
    title = "INFORME DE PANELES AGRUPADO POR ISP Y DOMINIO"; report_lines = []
    print(f"\n🔎 Buscando paneles en {len(ip_to_domains)} IPs..."); ip_to_panel = {}
    with ThreadPoolExecutor(max_workers=PANEL_SCAN_WORKERS) as executor:
        future_to_ip = {executor.submit(find_web_panel, ip): ip for ip in ip_to_domains.keys()}
        for future in tqdm(as_completed(future_to_ip), total=len(ip_to_domains), desc="Buscando Paneles"): ip_to_panel[future_to_ip[future]] = future.result()
    report_data = {}
    for ip, domains in ip_to_domains.items():
        isp = ip_details_cache.get(ip, {}).get('isp', 'Desconocido')
        if isp not in report_data: report_data[isp] = {}
        for domain in domains:
            if domain not in report_data[isp]: report_data[isp][domain] = {'ips': {}, 'url_count': 0}
            report_data[isp][domain]['ips'][ip] = ip_to_panel.get(ip, "No escaneado")
            report_data[isp][domain]['url_count'] = len([i for i in ip_to_urls.get(ip, []) if urlparse(i['url']).hostname == domain])
    for isp, domains_data in sorted(report_data.items()):
        report_lines.append(f"\n{Colors.OKCYAN}🏢 ISP: {isp}{Colors.ENDC}")
        for domain, data in sorted(domains_data.items()):
            url_count_str = f"({data['url_count']} URLs)"
            report_lines.append(f"  └─ {Colors.BOLD}Dominio:{Colors.ENDC} {domain} {url_count_str}")
            for ip, panel_info in data['ips'].items():
                country = ip_details_cache.get(ip, {}).get('country', 'N/A')
                ip_url_count = len(ip_to_urls.get(ip,[]))
                ip_url_count_str = f"({ip_url_count} URLs)"
                report_lines.append(f"    - {Colors.BOLD}IP:{Colors.ENDC} {ip.ljust(16)} {ip_url_count_str.ljust(12)} ({country}) | {Colors.BOLD}Panel:{Colors.ENDC} {panel_info}")
    print_report_to_console(title, report_lines); output_file = get_output_filename();
    if output_file: save_report_to_file(title, report_lines, output_file)

def generate_origin_report(ip_to_domains, ip_details_cache, ip_to_urls, source_url=None):
    title = "ANÁLISIS DE ORIGEN AVANZADO (EXCLUSIVO CLOUDFLARE)"; report_lines = []; source_domain = urlparse(source_url).hostname if source_url else None
    if source_domain:
        source_ip = next((ip for ip, domains in ip_to_domains.items() if source_domain in domains), None)
        if source_ip and 'cloudflare' not in ip_details_cache.get(source_ip, {}).get('isp', '').lower():
            details = ip_details_cache.get(source_ip); url_count = len(ip_to_urls.get(source_ip, [])); url_count_str = f"({url_count} URLs)"
            report_lines.append(f"{Colors.HEADER}--- Análisis de la URL de Origen de la Lista (No-Cloudflare) ---{Colors.ENDC}")
            report_lines.append(f"  └─ {Colors.BOLD}Dominio:{Colors.ENDC} {source_domain} {url_count_str} | {Colors.BOLD}IP:{Colors.ENDC} {source_ip} | {Colors.BOLD}ISP:{Colors.ENDC} {details.get('isp', 'N/A')} ({details.get('country', 'N/A')})")
            report_lines.append("-" * 120)
    cloudflare_domains_map = {ip: domains for ip, domains in ip_to_domains.items() if 'cloudflare' in ip_details_cache.get(ip, {}).get('isp', '').lower()}
    if not cloudflare_domains_map:
        if not report_lines: report_lines.append(f"{Colors.WARNING}No se encontraron dominios alojados en Cloudflare en la lista proporcionada.{Colors.ENDC}")
        print_report_to_console(title, report_lines); return
    cloudflare_ips = set(cloudflare_domains_map.keys()); report_data = {}
    print(f"\n🔎 Ejecutando análisis avanzado en dominios de Cloudflare..."); all_cf_domains = set.union(*cloudflare_domains_map.values())
    with ThreadPoolExecutor(max_workers=NORMAL_WORKERS) as executor:
        future_to_domain = {executor.submit(find_origin_ip_advanced, domain, cloudflare_ips): domain for domain in all_cf_domains}
        for future in tqdm(as_completed(future_to_domain), total=len(all_cf_domains), desc="Buscando Origen Avanzado"):
            domain = future_to_domain[future]; real_ip, method = future.result(); cf_ip = next((ip for ip, d in ip_to_domains.items() if domain in d), 'N/A')
            url_count = len([i for ip_addr in ip_to_urls for i in ip_to_urls[ip_addr] if urlparse(i['url']).hostname == domain])
            if real_ip:
                origin_details = get_ip_details(real_ip, ip_details_cache); origin_isp = origin_details.get('isp', 'Desconocido')
                if origin_isp not in report_data: report_data[origin_isp] = {}
                report_data[origin_isp][domain] = {'type': 'found', 'cf_ip': cf_ip, 'origin_ip': real_ip, 'origin_country': origin_details.get('country', 'N/A'), 'method': method, 'url_count': url_count}
            else:
                if 'Origen no encontrado' not in report_data: report_data['Origen no encontrado'] = {}
                report_data['Origen no encontrado'][domain] = {'type': 'not_found', 'cf_ip': cf_ip, 'url_count': url_count}
    if report_data: report_lines.append(f"{Colors.HEADER}--- Dominios de la Lista en Cloudflare ---{Colors.ENDC}")
    sorted_isps = sorted(report_data.keys(), key=lambda k: k == 'Origen no encontrado')
    for isp in sorted_isps:
        color = Colors.FAIL if isp == 'Origen no encontrado' else Colors.OKGREEN
        report_lines.append(f"\n{color}🏢 Proveedor de Origen: {Colors.BOLD}{isp}{Colors.ENDC}")
        for domain, data in sorted(report_data[isp].items()):
            url_count_str = f"({data['url_count']} URLs)"
            report_lines.append(f"  └─ {Colors.BOLD}Dominio:{Colors.ENDC} {domain} {url_count_str}")
            report_lines.append(f"    - {Colors.WARNING}Cloudflare IP:{Colors.ENDC} {data['cf_ip']}")
            if data['type'] == 'found':
                report_lines.append(f"    - {Colors.OKGREEN}IP Origen:{Colors.ENDC} {data['origin_ip']} ({data['origin_country']})")
                report_lines.append(f"      {Colors.OKCYAN}└─ Método de Detección: {data['method']}{Colors.ENDC}")
            else:
                report_lines.append(f"    - {Colors.FAIL}IP Origen: No encontrado{Colors.ENDC}")
    print_report_to_console(title, report_lines); output_file = get_output_filename();
    if output_file: save_report_to_file(title, report_lines, output_file)

def display_main_menu():
    os.system('clear' if os.name == 'posix' else 'cls')
    print("\n" * 2)
    print(f"{Colors.BOLD}{Colors.OKGREEN}======================================================={Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKGREEN}              ANALIZADOR DE SISTEMAS Y URLS            {Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKGREEN}======================================================={Colors.ENDC}\n")
    print("--- MENÚ PRINCIPAL ---\n")
    print("Seleccione una opción:\n"
          f"  {Colors.OKCYAN}1){Colors.ENDC} {Colors.BOLD}Análisis Completo de URL Única (Todo en Uno){Colors.ENDC}\n"
          f"  {Colors.OKCYAN}2){Colors.ENDC} Análisis de Listas (URL, M3U, Archivo)\n"
          f"  {Colors.HEADER}3){Colors.ENDC} Herramienta de Conversión de URL de IPTV\n"
          f"  {Colors.OKCYAN}4){Colors.ENDC} Herramienta de Diagnóstico y Latencia\n"
          f"  {Colors.OKBLUE}5){Colors.ENDC} Análisis Rápido de Servidor y Seguridad\n\n"
          f"  {Colors.WARNING}6) Salir{Colors.ENDC}")
    while True:
        choice = input(f"\n{Colors.OKCYAN}{Colors.BOLD}Elige una opción (1-6): {Colors.ENDC}");
        if choice in ['1', '2', '3', '4', '5', '6']: return choice
        print(f"{Colors.FAIL}Opción no válida. Por favor, introduce un número del 1 al 6.{Colors.ENDC}")

def display_analysis_submenu():
    """Muestra el menú para elegir qué informe generar con los datos en caché."""
    print("\n" + "="*60)
    print(f"{Colors.BOLD}{'MENÚ DE INFORMES (DATOS YA CARGADOS)'.center(60)}{Colors.ENDC}")
    print("="*60)
    print("\nSeleccione un tipo de informe para generar:\n"
          f"  {Colors.OKCYAN}1){Colors.ENDC} Informe Básico (Agrupado por ISP)\n"
          f"  {Colors.OKCYAN}2){Colors.ENDC} Informe de Canales M3U\n"
          f"  {Colors.OKCYAN}3){Colors.ENDC} Informe de Paneles Web\n"
          f"  {Colors.OKCYAN}4){Colors.ENDC} Informe de Origen (Cloudflare)\n\n"
          f"  {Colors.WARNING}5) Analizar una nueva lista / Volver al menú principal{Colors.ENDC}")
    while True:
        choice = input(f"\n{Colors.OKCYAN}{Colors.BOLD}Elige una opción (1-5): {Colors.ENDC}");
        if choice in ['1', '2', '3', '4', '5']: return choice
        print(f"{Colors.FAIL}Opción no válida. Por favor, introduce un número del 1 al 5.{Colors.ENDC}")

def handle_list_analysis():
    """
    Gestiona el flujo de análisis de listas: carga datos si es necesario
    y luego muestra el submenú de informes para que el usuario elija.
    """
    global analysis_cache
    
    if not analysis_cache["is_analyzed"]:
        print("\n--- PASO 1: CARGAR DATOS ---")
        content_to_analyze, source_url = get_input_source()
        
        if content_to_analyze and content_to_analyze.strip():
            start_time = time.time()
            
            (ip_to_domains, 
             ip_details_cache, 
             ip_to_urls, 
             timed_out_urls) = run_list_analysis(content_to_analyze, source_url=source_url)
            
            end_time = time.time()

            if ip_to_domains:
                analysis_cache.update({
                    "is_analyzed": True,
                    "ip_to_domains": ip_to_domains,
                    "ip_details_cache": ip_details_cache,
                    "ip_to_urls": ip_to_urls,
                    "source_url": source_url,
                    "timeouts": timed_out_urls
                })
                print(f"\n{Colors.OKGREEN}Reconocimiento completado en {end_time - start_time:.2f} segundos.{Colors.ENDC}")
                if timed_out_urls > 0:
                    print(f"{Colors.WARNING}Se omitieron {timed_out_urls} URLs por exceder el tiempo de espera.{Colors.ENDC}")
            else:
                print(f"\n{Colors.FAIL}El análisis no encontró IPs válidas. Volviendo al menú principal.{Colors.ENDC}")
                return 
        else:
            if content_to_analyze is not None:
                print(f"{Colors.WARNING}No se proporcionó contenido válido. Volviendo al menú principal.{Colors.ENDC}")
            return

    while True:
        report_choice = display_analysis_submenu()
        
        cached_data = {
            "ip_to_domains": analysis_cache["ip_to_domains"],
            "ip_details_cache": analysis_cache["ip_details_cache"],
            "ip_to_urls": analysis_cache["ip_to_urls"],
            "source_url": analysis_cache["source_url"]
        }

        if report_choice == '1':
            generate_grouped_report(**cached_data)
        elif report_choice == '2':
            generate_channel_report(**cached_data)
        elif report_choice == '3':
            generate_panel_report(**cached_data)
        elif report_choice == '4':
            generate_origin_report(**cached_data)
        elif report_choice == '5':
            reset_cache()
            break 
            
        input(f"\n{Colors.OKBLUE}Informe generado. Presiona Enter para volver al menú de informes...{Colors.ENDC}")

def get_input_source():
    print("\n¿Desde dónde quieres cargar la lista?\n" f"    {Colors.OKCYAN}1){Colors.ENDC} Desde una URL\n" f"    {Colors.OKCYAN}2){Colors.ENDC} Desde un archivo local\n" f"    {Colors.OKCYAN}3){Colors.ENDC} Pegar contenido directamente")
    while True:
        choice = input(f"\n{Colors.OKCYAN}{Colors.BOLD}Elige una opción (1-3): {Colors.ENDC}")
        if choice == '1':
            url = input(f"{Colors.OKCYAN}Introduce la URL del archivo: {Colors.ENDC}");
            try: print(f"📡 Descargando lista desde: {url}"); content = requests.get(url, timeout=30, headers={'User-Agent': 'Mozilla/5.0'}).text; return content, url
            except requests.RequestException as e: print(f"{Colors.FAIL}Error al descargar la URL: {e}{Colors.ENDC}"); return None, None
        elif choice == '2':
            file_path = input(f"{Colors.OKCYAN}Introduce la ruta al archivo local: {Colors.ENDC}")
            try: print(f"📂 Leyendo archivo: {file_path}"); f = open(file_path, 'r', encoding='utf-8', errors='ignore'); content = f.read(); f.close(); return content, None
            except FileNotFoundError: print(f"{Colors.FAIL}Error: El archivo '{file_path}' no fue encontrado.{Colors.ENDC}"); return None, None
        elif choice == '3':
            print("📋 Pega tu contenido a continuación. Presiona Ctrl+D (Linux/Mac) o Ctrl+Z y Enter (Windows) al terminar."); return sys.stdin.read(), None
        else: print(f"{Colors.FAIL}Opción no válida.{Colors.ENDC}")

def get_output_filename():
    while True:
        save = input(f"\n{Colors.OKCYAN}{Colors.BOLD}¿Quieres guardar el informe en un archivo de texto? (s/n): {Colors.ENDC}").lower()
        if save in ['s', 'si']: 
            default_name = f"informe_{int(time.time())}.txt"
            filename = input(f"{Colors.OKCYAN}Introduce el nombre del archivo (dejar en blanco para '{default_name}'): {Colors.ENDC}")
            return filename or default_name
        elif save in ['n', 'no']: return None
        else: print(f"{Colors.FAIL}Respuesta no válida. Por favor, responde 's' o 'n'.{Colors.ENDC}")

if __name__ == "__main__":
    while True:
        main_choice = display_main_menu()
        
        if main_choice == '1':
            full_single_url_analysis()
        elif main_choice == '2':
            handle_list_analysis()
        elif main_choice == '3':
            handle_url_conversion()
        elif main_choice == '4':
            measure_latency()
        elif main_choice == '5':
            analyze_server_fast()
        elif main_choice == '6':
            print(f"{Colors.OKBLUE}¡Hasta pronto!{Colors.ENDC}")
            break
            
        input(f"\n{Colors.OKBLUE}Presiona Enter para volver al menú principal...{Colors.ENDC}")