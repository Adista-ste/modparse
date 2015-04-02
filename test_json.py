#!/bin/env python

import sys, re, datetime, pprint, json

# Tentative de sérialiser la liste en JSON dans un fichier (test)
test={'ModSec': {'Producer': 'ModSecurity for Apache/2.7.3 (http://www.modsecurity.org/); OWASP_CRS/2.2.6.',
            'Server': 'Apache/2.2.15 (CentOS)',
            'Stopwatch': '1424657375852470 758421 (- - -)',
            'Stopwatch2': '1424657375852470 758421; combined=4429, p1=811, p2=1530, p3=0, p4=0, p5=2086, sr=228, sw=2, l=0, gc=0',
            'list_mesg': [{'msgdatas': {'file': '/etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_60_correlation.conf',
                                        'id': '981203',
                                        'line': '33',
                                        'msg': 'Inbound Anomaly Score (Total Inbound Score: 3, SQLi=, XSS=): Rogue web site crawler'},
                           'msglevel': 'Warning',
                           'msgmessage': 'Operator LT matched 5 at TX:inbound_anomaly_score'}]},
 'data': {'date': datetime.datetime(2015, 2, 23, 3, 9, 36),
          'ipd': '149.255.137.28',
          'ips': '80.35.138.190',
          'pd': '80',
          'ps': '53803',
          'uid': 'VOqL35X-iRwAAGitWLEAAAAf'},
 'id': '2d53de02',
 'req': {'Accept': 'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.3',
         'Host': 'www.renov-assistance.fr',
         'req': 'GET /wp-content/plugins/captcha/captcha.php HTTP/1.1'},
 'resp': {'Connection': 'close',
          'Content-Encoding': 'gzip',
          'Content-Type': 'text/html; charset=UTF-8',
          'Transfer-Encoding': 'chunked',
          'Vary': 'Accept-Encoding,User-Agent',
          'code': '500',
          'msg': 'Internal Server Error',
          'resp': 'HTTP/1.1 500 Internal Server Error',
          'version': 'HTTP/1.1'}}
with open('/tmp/test.json',w) as outfile:
	json.dump(test, outfile)
