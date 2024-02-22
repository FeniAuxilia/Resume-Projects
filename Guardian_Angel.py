#WEB APPLICATION FIREWALL

from flask import Flask
app = Flask(__name__)

import re
import os
import json
import requests
import logging
from datetime import datetime, timedelta

class WAF:
    def __init__(self, b_ips=[], b_useragents=[], b_urls=[], w_ips=[], w_useragents=[], w_urls=[], log=None, blockTime=None, limitedRate=None):
        self.b_ips = b_ips
        self.b_useragaents = b_useragents
        self.b_urls = b_urls
        self.w_ips = w_ips
        self.w_useragents = w_useragents
        self.w_urls = w_urls
        self.log = log
        self.blockTime = blockTime
        self.limitedRate = limitedRate
        self.requests = []
        
    def b_ip(self, ip):
        self.b_ips.append(ip)
        
    def b_useragent(self, useragent):
        self.b_useragents.append(useragent)
        
    def b_url(self, url):
        self.b_urls.append(url)
        
    def w_ip(self, ip):
        self.w_ips.append(ip)
        
    def w_useragent(self, useragent):
        self.w_useragents.append(useragent)
        
    def w_url(self, url):
        self.w_urls.append(url)
        
    def checkIP(self, ip):
        if ip in self.b_ips:
            return True
        elif ip in self.w_ips:
            return False
        else:
            return False
        
    def checkUseragent(self, useragent):
        for ua in self.b_useragents:
            if re.search(ua, useragent):
                return True
        for ua in self.w_useragents:
            if re.search(ua, useragent):
                return False
        return False
    
    def checkUrl(self, url):
        for u in self.b_urls:
            if re.search(u, url):
                return True
        for u in self.w_urls:
            if re.search(u, url):
                return False
        return False
    
    def logRequest(self, req):
        if self.log:
            with open(self.log, 'a') as file:
                file.write(json.dumps(req) + '\n')
                
    def blockRequest(self, req):
        self.requests.append(req)
        if self.blockTime:
            self.b_ip(req['ip_address'])
        self.logRequest(req)
        
    def checkLimitedRate(self, ip):
        if self.limitedRate:
            n = datetime.utcnow()
            cutoff_time = n - timedelta(seconds=self.rate_limit)
            requests = [r for r in self.requests if r['ip_address'] == ip and r['time'] > cutoff_time]
            if len(requests) > self.limitedRate:
                return True
            return False
        
    def handleRequest(self, req):
        ip = req['ip_address']
        ua = req['user_agent']
        url = req['url']
        if self.checkIP(ip) or self.checkUseragent(ua) or self.checkUrl(url):
            self.blockRequest(req)
            return True
        elif self.checkLimitedRate(ip):
            self.blockRequest(req)
            return True
        else:
            self.logRequest(req)
            return False
        
    def getRquestData(req):
        data = {
            'ip_address': req.remote_addr,
            'user_agent': req.headers.get('User-Agent'),
            'url': req.url,
            'method': req.method,
            'time': datetime.utcnow(),
            }
        return data

    def main():
        logging.basicConfig(filename='firewall.log', level=logging.INFO)
        
        Firewall = WAF(b_ips=['192.168.1.1'], 
                            b_useragents=['^curl/.*', '^wget/.*'], 
                            b_urls=['.*\.php'], 
                            w_ips=['10.0.0.1'], 
                            w_useragents=['^Mozilla/.*'], 
                            w_urls=['/healthcheck'])
       
        rate_limit = 10
        block_time = 300
        
        app.run(host='0.0.0.0', port=5000)
        
    main()