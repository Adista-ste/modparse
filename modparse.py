#!/bin/env python

import sys, re, datetime, pprint

file=sys.argv[1]
index = int(sys.argv[2])
choix=sys.argv[3]

fileall = open(file, 'r').read()

filetrans = re.sub(r'(--\w+-Z--\n)',r'\1###############\n', fileall)
attaques = re.split(r'\n###############\n', filetrans)


sectiona = re.compile(r'-*(?P<id>\w+)-A--')
sectiona_content = re.compile(r'^\[(?P<date>.+)\] (?P<uid>.+) (?P<ips>[\d\.]+) (?P<ps>[\d]+) (?P<ipd>[\d\.]+) (?P<pd>[\d]+)$')

sectionb = re.compile(r'(?P<id>\w+)-B--')
sectionb_req = re.compile(r'(?P<req>.+)')
sectionb_content = re.compile(r'^(?P<header>[A-Z][a-z\-]+): (?P<value>.+)$')

sectionc = re.compile(r'(?P<id>\w+)-C--')
sectionc_reqbody = re.compile(r'(?P<req>.+)')

sectionf = re.compile(r'(?P<id>\w+)-F--')
sectionf_resp = re.compile(r'(?P<resp>.+)')
sectionf_resp_all = re.compile(r'^(?P<version>[A-Z\\0-9\.]+) (?P<code>[0-9]+) (?P<msg>.*)$')
sectionf_content = re.compile(r'^(?P<header>.+): (?P<value>.+)$')

sectionh = re.compile(r'(?P<id>\w+)-H--')
sectionh_lines = re.compile(r'(?P<specialheader>\w+): (?P<specialvalue>.*)$')
sectionh_messages = re.compile(r'^(?P<msglevel>\w+)\. (?P<msgmessage>.*)\. (?P<msgdata>\[.*\])$')
sectionh_messages_params = re.compile(r'^\[(?P<msgparam>\w+) \"(?P<msgvalue>.*)\"\]$')

sectionz = re.compile(r'(?P<id>\w+)-Z--')


detectionl = []

for attaque in attaques:
	sections = re.split('\n--',attaque)
	detectiond = {}
	for section in sections:
		if sectiona.match(section):
			lines = section.split('\n')
			a_titleres = sectiona.match(lines[0])
			a_title = a_titleres.groupdict()
			a_contentres = sectiona_content.match(lines[1]) if lines[1] <>  "" else ""
			if a_contentres:
				a_content = a_contentres.groupdict() if a_contentres <> "" else None
				a_content['date'] = re.sub(' \+\w{4}$','', a_content['date'])
				a_content['date'] = datetime.datetime.strptime( a_content['date'], '%d/%b/%Y:%X')
				a_content['datestr'] = datetime.datetime.strftime( a_content['date'], '%Y/%m/%d-%X')
				detectiond['id'] = a_title['id']
				detectiond['data'] = a_content
#				detectiond['data'] = {
#							'UID': a_content['uid'],
#							'date': a_content['date'],
#							'ips': a_content['ips'],
#							'ps': a_content['ps'],
#							'ipd': a_content['ipd'],
#							'pd': a_content['pd'],
#							}
				continue
		if sectionb.match(section):
			lines = section.split('\n')
			lines.pop(0)
			b_reqres = sectionb_req.match(lines[0])
			b_req = b_reqres.groupdict()
			detectiond['req'] = { 'req': b_req['req'] }
			lines.pop(0)
			for line in lines:
				try:	
					b_contentres = sectionb_content.match(line)
					b_content_ini = b_contentres.groupdict()
					detectiond['req'].update({ b_content_ini['header'] : b_content_ini['value'], })
				except:
					pass
			continue
		if sectionf.match(section):
			lines = section.split('\n')
			lines.pop(0)

			try:
				f_respres = sectionf_resp.match(lines[0])
				f_resp = f_respres.groupdict()
			except:
				pass

			try:
				f_respallres = sectionf_resp_all.match(lines[0])
				f_respall = f_respallres.groupdict()
			except:
				pass

			try:
				detectiond['resp'] = { 'resp': f_resp['resp'] }
				detectiond['resp'].update(f_respall)
			except:
				pass

			lines.pop(0)

			for line in lines:
				try:	
					f_contentres = sectionf_content.match(line)
					f_content = f_contentres.groupdict()
					detectiond['resp'].update({ f_content['header'] : f_content['value'] })
				except:
					pass
			continue
		if sectionh.match(section):
			detectiond['ModSec'] = {}
			lines = section.split('\n')
			lines.pop(0)

			listmesg = []
			for line in lines:
#				if re.search(r'^\s*$', line) is False:	
				try:
					h_lineres = sectionh_lines.match(line)
					h_line = h_lineres.groupdict()
#				else:
				except:
					continue
				
				if h_line['specialheader'] == "Message":
					h_mesgres = sectionh_messages.match(h_line['specialvalue'])
					try:
						h_mesg = h_mesgres.groupdict()
					except:
						print "h_mesg : %s " % h_mesg
						pass
					try:
						h_mesg['msgdata'] = re.sub('\] \[',']_-_[',h_mesg['msgdata'])
						h_mesg_params_array = h_mesg['msgdata'].split('_-_')
					except:
						pass
					del h_mesg['msgdata']
					if not 'msgdatas' in h_mesg:
						h_mesg['msgdatas'] = {}
					i = 0
					for h_mesg_params in h_mesg_params_array:
						h_mesg_paramsres = sectionh_messages_params.match(h_mesg_params)
						h_mesg_params = h_mesg_paramsres.groupdict()
						if h_mesg_params['msgparam'] in h_mesg['msgdatas']:
							i+=1
							h_mesg['msgdatas'].update({ h_mesg_params['msgparam']+str(i) : h_mesg_params['msgvalue'] })
						else:
							h_mesg['msgdatas'].update({ h_mesg_params['msgparam'] : h_mesg_params['msgvalue'] })
					listmesg.append(h_mesg)
				else:
					detectiond['ModSec'].update({h_line['specialheader'] : h_line['specialvalue']})
				if len(listmesg) > 0:
					detectiond['ModSec'].update({ 'list_mesg' : listmesg })
				else:
					detectiond['ModSec'].update({ 'list_mesg' : [h_mesg] })
				#detectiond['ModSec'].update(h_mesg)
				#detectiond['ModSec']['debug'] = []
				#detectiond['ModSec']['debug'].append(listmesg)
			del listmesg
			continue
		if sectionz.match(section):
			detectionl.append(detectiond)
			continue
		if detectiond <> {}:
			detectionl.append(detectiond)

#pprint.pprint(detectionl[index])

for at in detectionl:
	for msg in at['ModSec']['list_mesg']:
		print "%5s;%5s;%100s;%s" % (detectionl.index(at), msg['msgdatas']['id'], at['req']['req'], at['data']['datestr'])

#print len(detectionl)
#print attaques[index]
#pprint.pprint(detectionl[index])


#	
#	{'ModSec': {'Producer': 'ModSecurity for Apache/2.7.3 (http://www.modsecurity.org/); OWASP_CRS/2.2.6.',
#	            'Server': 'Apache/2.2.15 (CentOS)',
#	            'Stopwatch': '1424657375852470 758421 (- - -)',
#	            'Stopwatch2': '1424657375852470 758421; combined=4429, p1=811, p2=1530, p3=0, p4=0, p5=2086, sr=228, sw=2, l=0, gc=0',
#	            'list_mesg': [{'msgdatas': {'file': '/etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_60_correlation.conf',
#	                                        'id': '981203',
#	                                        'line': '33',
#	                                        'msg': 'Inbound Anomaly Score (Total Inbound Score: 3, SQLi=, XSS=): Rogue web site crawler'},
#	                           'msglevel': 'Warning',
#	                           'msgmessage': 'Operator LT matched 5 at TX:inbound_anomaly_score'}]},
#	 'data': {'date': datetime.datetime(2015, 2, 23, 3, 9, 36),
#	          'ipd': '149.255.137.28',
#	          'ips': '80.35.138.190',
#	          'pd': '80',
#	          'ps': '53803',
#	          'uid': 'VOqL35X-iRwAAGitWLEAAAAf'},
#	 'id': '2d53de02',
#	 'req': {'Accept': 'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.3',
#	         'Host': 'www.renov-assistance.fr',
#	         'req': 'GET /wp-content/plugins/captcha/captcha.php HTTP/1.1'},
#	 'resp': {'Connection': 'close',
#	          'Content-Encoding': 'gzip',
#	          'Content-Type': 'text/html; charset=UTF-8',
#	          'Transfer-Encoding': 'chunked',
#	          'Vary': 'Accept-Encoding,User-Agent',
#	          'code': '500',
#	          'msg': 'Internal Server Error',
#	          'resp': 'HTTP/1.1 500 Internal Server Error',
#	          'version': 'HTTP/1.1'}}
#	
