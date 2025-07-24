#!/usr/bin/env python3

import argparse
import sys
import os
from datetime import datetime

__author__ = 'SayerLinux'
__email__ = 'SaudiSayer@gmail.com'
__version__ = '1.0.0'

class WebHack:
    def __init__(self):
        self.banner = '''
        ██╗    ██╗███████╗██████╗     ██╗  ██╗ █████╗  ██████╗██╗  ██╗
        ██║    ██║██╔════╝██╔══██╗    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
        ██║ █╗ ██║█████╗  ██████╔╝    ███████║███████║██║     █████╔╝ 
        ██║███╗██║██╔══╝  ██╔══██╗    ██╔══██║██╔══██║██║     ██╔═██╗ 
        ╚███╔███╔╝███████╗██████╔╝    ██║  ██║██║  ██║╚██████╗██║  ██╗
         ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                By: SayerLinux
        '''
        self.parser = self._create_parser()
        
    def _create_parser(self):
        parser = argparse.ArgumentParser(
            description='Web-Hack - Advanced Security Vulnerability Scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter)
        
        parser.add_argument('-t', '--target', 
                          help='Target URL or IP address')
        parser.add_argument('-p', '--port',
                          help='Target port number')
        parser.add_argument('--scan-type',
                          choices=['quick', 'full', 'custom'],
                          default='quick',
                          help='Type of scan to perform')
        parser.add_argument('-o', '--output',
                          help='Output file for scan results')
        return parser

    def check_platform(self):
        if sys.platform != 'linux':
            print('Error: Web-Hack only supports Linux operating systems')
            sys.exit(1)

    def run(self):
        self.check_platform()
        print(self.banner)
        args = self.parser.parse_args()
        
        if not args.target:
            self.parser.print_help()
            sys.exit(1)
            
        print(f'Starting scan on {args.target} at {datetime.now()}')
        # TODO: Implement scanning functionality

def main():
    scanner = WebHack()
    scanner.run()

if __name__ == '__main__':
    main()