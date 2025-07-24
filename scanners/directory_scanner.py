#!/usr/bin/env python3

import requests
from rich.console import Console
from rich.progress import Progress
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class DirectoryScanner:
    def __init__(self, target, wordlist=None):
        self.target = target
        self.console = Console()
        self.findings = []
        self.headers = {
            'User-Agent': 'Web-Hack Security Scanner v1.0 (SayerLinux)'
        }
        # قائمة المسارات الشائعة للفحص
        self.default_paths = [
            # مسارات إدارة
            'admin/', 'administrator/', 'login/', 'wp-admin/',
            'admin.php', 'admin.html', 'administrator.php', 'login.php',
            
            # ملفات التكوين
            'config.php', 'configuration.php', 'config.inc.php',
            'wp-config.php', '.env', 'config.yml', 'config.xml',
            
            # نصوص معلومات
            'phpinfo.php', 'info.php', 'test.php', 'readme.html',
            'README.md', 'changelog.txt', 'license.txt',
            
            # مسارات النظام
            '.git/', '.svn/', '.htaccess', 'robots.txt',
            'sitemap.xml', 'crossdomain.xml',
            
            # مجلدات شائعة
            'backup/', 'backups/', 'database/', 'db/',
            'logs/', 'temp/', 'tmp/', 'images/',
            'uploads/', 'files/', 'admin/backup/',
            
            # ملفات API
            'api/', 'api/v1/', 'api/v2/', 'swagger/',
            'swagger-ui.html', 'api-docs/', 'graphql',
            
            # صفحات الخطأ
            'error/', '404.php', '500.php', 'error.log',
            
            # ملفات حساسة
            '.DS_Store', 'web.config', '.htpasswd',
            'composer.json', 'package.json', 'yarn.lock',
            'Gemfile', 'requirements.txt'
        ]
        self.wordlist = wordlist if wordlist else self.default_paths
        self.max_threads = 10
        self.request_delay = 0.1  # تأخير بين الطلبات

    def normalize_url(self, url):
        """تطبيع عنوان URL"""
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        if not url.endswith('/'):
            url += '/'
        return url

    def check_path(self, base_url, path):
        """فحص مسار واحد"""
        url = urljoin(base_url, path)
        try:
            response = requests.get(
                url,
                headers=self.headers,
                allow_redirects=False,
                timeout=5
            )
            
            # التحقق من الاستجابة
            if response.status_code in [200, 201, 203]:
                self.findings.append({
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('content-type', ''),
                    'risk_level': 'HIGH' if self._is_sensitive_path(path) else 'MEDIUM'
                })
            elif response.status_code in [301, 302, 307, 308]:
                redirect_url = response.headers.get('location', '')
                self.findings.append({
                    'url': url,
                    'status_code': response.status_code,
                    'redirect_to': redirect_url,
                    'risk_level': 'LOW'
                })

            time.sleep(self.request_delay)  # تأخير بين الطلبات

        except requests.exceptions.RequestException:
            pass

    def _is_sensitive_path(self, path):
        """تحديد ما إذا كان المسار حساسًا"""
        sensitive_keywords = [
            'admin', 'config', 'backup', 'db', 'database',
            'log', 'password', 'secret', 'key', '.git',
            '.env', 'phpinfo', 'api'
        ]
        return any(keyword in path.lower() for keyword in sensitive_keywords)

    def scan(self):
        """تنفيذ المسح الكامل"""
        base_url = self.normalize_url(self.target)
        total_paths = len(self.wordlist)
        
        with Progress() as progress:
            task = progress.add_task(
                '[cyan]Scanning directories...',
                total=total_paths
            )
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_path = {}
                for path in self.wordlist:
                    future = executor.submit(self.check_path, base_url, path)
                    future_to_path[future] = path

                for future in as_completed(future_to_path):
                    progress.update(task, advance=1)

        return self.findings

    def generate_report(self):
        """إنشاء تقرير بنتائج المسح"""
        self.console.print('\n[bold green]===== Directory Scan Report =====[/bold green]')
        self.console.print(f'Target: {self.target}')
        self.console.print(f'Total paths scanned: {len(self.wordlist)}\n')

        if not self.findings:
            self.console.print('[green]No sensitive directories or files found![/green]')
            return

        # تصنيف النتائج حسب مستوى الخطورة
        high_risk = [f for f in self.findings if f.get('risk_level') == 'HIGH']
        medium_risk = [f for f in self.findings if f.get('risk_level') == 'MEDIUM']
        low_risk = [f for f in self.findings if f.get('risk_level') == 'LOW']

        # عرض النتائج عالية الخطورة
        if high_risk:
            self.console.print('\n[bold red]High Risk Findings:[/bold red]')
            for finding in high_risk:
                self._print_finding(finding)

        # عرض النتائج متوسطة الخطورة
        if medium_risk:
            self.console.print('\n[bold yellow]Medium Risk Findings:[/bold yellow]')
            for finding in medium_risk:
                self._print_finding(finding)

        # عرض النتائج منخفضة الخطورة
        if low_risk:
            self.console.print('\n[bold blue]Low Risk Findings:[/bold blue]')
            for finding in low_risk:
                self._print_finding(finding)

        # إحصائيات
        self.console.print('\n[bold blue]Statistics:[/bold blue]')
        self.console.print(f'Total findings: {len(self.findings)}')
        self.console.print(f'High risk: {len(high_risk)}')
        self.console.print(f'Medium risk: {len(medium_risk)}')
        self.console.print(f'Low risk: {len(low_risk)}')

    def _print_finding(self, finding):
        """طباعة تفاصيل النتيجة"""
        self.console.print(f"URL: {finding['url']}")
        self.console.print(f"Status Code: {finding['status_code']}")
        
        if 'content_length' in finding:
            self.console.print(f"Content Length: {finding['content_length']}")
        if 'content_type' in finding:
            self.console.print(f"Content Type: {finding['content_type']}")
        if 'redirect_to' in finding:
            self.console.print(f"Redirects To: {finding['redirect_to']}")
            
        self.console.print('')  # سطر فارغ للفصل