#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress
from urllib.parse import urljoin, urlparse
import re

class XSSScanner:
    def __init__(self, target):
        self.target = target
        self.console = Console()
        self.vulnerabilities = []
        self.visited_urls = set()
        self.forms = []
        self.headers = {
            'User-Agent': 'Web-Hack Security Scanner v1.0 (SayerLinux)'
        }
        # نماذج XSS للاختبار
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '\'><img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"onmouseover=alert(1)',
            'javascript:alert(1)'
        ]

    def normalize_url(self, url):
        """تطبيع عنوان URL"""
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        return url

    def is_same_domain(self, url):
        """التحقق مما إذا كان URL من نفس النطاق"""
        return urlparse(url).netloc == urlparse(self.target).netloc

    def extract_forms(self, url):
        """استخراج النماذج من الصفحة"""
        try:
            response = requests.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            self.console.print(f'[red]Error extracting forms from {url}: {str(e)}[/red]')
            return []

    def test_xss_in_form(self, form, url):
        """اختبار XSS في النموذج"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea'])

        # تجميع بيانات النموذج
        form_data = {}
        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')
            
            if input_name:
                if input_type == 'submit':
                    form_data[input_name] = input_field.get('value', '')
                else:
                    # اختبار كل payload في كل حقل
                    for payload in self.xss_payloads:
                        form_data[input_name] = payload
                        
                        try:
                            if method == 'post':
                                response = requests.post(
                                    urljoin(url, action),
                                    data=form_data,
                                    headers=self.headers,
                                    allow_redirects=False
                                )
                            else:
                                response = requests.get(
                                    urljoin(url, action),
                                    params=form_data,
                                    headers=self.headers,
                                    allow_redirects=False
                                )

                            # التحقق من وجود payload في الاستجابة
                            if payload in response.text:
                                self.vulnerabilities.append({
                                    'type': 'XSS',
                                    'url': url,
                                    'method': method,
                                    'form_action': action,
                                    'vulnerable_parameter': input_name,
                                    'payload': payload
                                })
                                # التوقف بعد العثور على ثغرة
                                return

                        except Exception as e:
                            self.console.print(f'[red]Error testing form at {url}: {str(e)}[/red]')

    def scan_url(self, url):
        """فحص URL واحد"""
        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        forms = self.extract_forms(url)

        for form in forms:
            self.test_xss_in_form(form, url)

    def crawl_and_scan(self, url, max_urls=10):
        """تصفح الموقع وفحص الصفحات"""
        try:
            response = requests.get(url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # استخراج جميع الروابط
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
            task = progress.add_task('[cyan]Scanning for XSS vulnerabilities...', total=100)
            
            # فحص الصفحة الرئيسية أولاً
            self.scan_url(url)
            progress.update(task, advance=50)
            
            # تصفح وفحص الصفحات الأخرى
            self.crawl_and_scan(url)
            progress.update(task, advance=50)

        return self.vulnerabilities

    def generate_report(self):
        """إنشاء تقرير بنتائج المسح"""
        self.console.print('\n[bold green]===== XSS Scan Report =====[/bold green]')
        self.console.print(f'Target: {self.target}')
        self.console.print(f'Pages scanned: {len(self.visited_urls)}\n')

        if not self.vulnerabilities:
            self.console.print('[green]No XSS vulnerabilities found![/green]')
            return

        for vuln in self.vulnerabilities:
            self.console.print(f'[red]XSS Vulnerability Found![/red]')
            self.console.print(f'URL: {vuln["url"]}')
            self.console.print(f'Method: {vuln["method"].upper()}')
            self.console.print(f'Form Action: {vuln["form_action"]}')
            self.console.print(f'Vulnerable Parameter: {vuln["vulnerable_parameter"]}')
            self.console.print(f'Payload: {vuln["payload"]}\n')