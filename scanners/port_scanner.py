#!/usr/bin/env python3

import nmap
from rich.console import Console
from rich.progress import Progress
import socket
import sys

class PortScanner:
    def __init__(self, target, ports=None):
        self.target = target
        self.ports = ports if ports else '1-1000'
        self.console = Console()
        self.nm = nmap.PortScanner()
        self.results = []

    def is_valid_target(self):
        """التحقق من صحة الهدف"""
        try:
            socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            return False

    def scan_tcp_ports(self):
        """مسح المنافذ TCP"""
        try:
            with Progress() as progress:
                task = progress.add_task('[cyan]Scanning TCP ports...', total=100)
                
                # تنفيذ المسح باستخدام nmap
                self.nm.scan(self.target, self.ports, arguments='-sS -sV -Pn')
                progress.update(task, completed=100)

                # معالجة النتائج
                for host in self.nm.all_hosts():
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            state = self.nm[host][proto][port]['state']
                            service = self.nm[host][proto][port]['name']
                            version = self.nm[host][proto][port]['version']
                            
                            self.results.append({
                                'port': port,
                                'protocol': proto,
                                'state': state,
                                'service': service,
                                'version': version
                            })

        except Exception as e:
            self.console.print(f'[red]Error during port scan: {str(e)}[/red]')
            return False

        return True

    def scan(self):
        """تنفيذ المسح الكامل"""
        if not self.is_valid_target():
            self.console.print(f'[red]Invalid target: {self.target}[/red]')
            return False

        return self.scan_tcp_ports()

    def generate_report(self):
        """إنشاء تقرير بنتائج المسح"""
        self.console.print('\n[bold green]===== Port Scan Report =====[/bold green]')
        self.console.print(f'Target: {self.target}')
        self.console.print(f'Ports scanned: {self.ports}\n')

        if not self.results:
            self.console.print('[yellow]No open ports found.[/yellow]')
            return

        # تصنيف النتائج حسب الحالة
        open_ports = [r for r in self.results if r['state'] == 'open']
        filtered_ports = [r for r in self.results if r['state'] == 'filtered']
        closed_ports = [r for r in self.results if r['state'] == 'closed']

        # عرض المنافذ المفتوحة
        if open_ports:
            self.console.print('[bold red]Open Ports:[/bold red]')
            for result in open_ports:
                self.console.print(
                    f"Port {result['port']}/{result['protocol']}: "
                    f"{result['service']} "
                    f"({result['version'] if result['version'] else 'unknown version'})"
                )

        # عرض المنافذ المفلترة
        if filtered_ports:
            self.console.print('\n[bold yellow]Filtered Ports:[/bold yellow]')
            for result in filtered_ports:
                self.console.print(f"Port {result['port']}/{result['protocol']}")

        # إحصائيات
        self.console.print('\n[bold blue]Statistics:[/bold blue]')
        self.console.print(f'Total ports scanned: {len(self.results)}')
        self.console.print(f'Open ports: {len(open_ports)}')
        self.console.print(f'Filtered ports: {len(filtered_ports)}')
        self.console.print(f'Closed ports: {len(closed_ports)}')