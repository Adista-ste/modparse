#!/bin/env python

import sys, re, datetime, pprint

file=sys.argv[1]


fileall = open(file, 'r').read()

filetrans = re.sub(r'(--\w+-Z--\n)',r'\1###############\n', fileall)
attaques = re.split(r'\n###############\n', filetrans)


sectiona = re.compile("(?P<id>\w+)-A--")
sectiona_content = re.compile("^\[(?P<date>.+)\] (?P<uid>[\w-]+) (?P<ips>[\d\.]+) (?P<ps>[\d]+) (?P<ipd>[\d\.]+) (?P<pd>[\d]+)$")

sectionb = re.compile("(?P<id>\w+)-B--")
sectionb_req = re.compile("(?P<req>.+)")
sectionb_content = re.compile("^(?P<header>[A-Z][a-z\-]+): (?P<value>.+)$")

sectionc = re.compile("(?P<id>\w+)-C--")
sectionc_reqbody = re.compile("(?P<req>.+)")

sectionf = re.compile("(?P<id>\w+)-F--")
sectionf_resp = re.compile("(?P<resp>.+)")
sectionf_resp_all = re.compile("^(?P<version>[A-Z\\0-9\.]+) (?P<code>[0-9]+) (?P<msg>.*)$")
sectionf_content = re.compile("^(?P<header>.+): (?P<value>.+)$")

sectionh = re.compile("(?P<id>\w+)-H--")
sectionh_lines = re.compile("(?P<specialheader>\w+): (?P<specialvalue>.*)$")
sectionh_messages = re.compile("^(?P<msglevel>\w+)\. (?P<msgmessage>.*)\. (?P<msgdata>\[.*\])$")
sectionh_messages_params = re.compile("^\[(?P<msgparam>\w+) \"(?P<msgvalue>.*)\"\]$")

sectionz = re.compile("(?P<id>\w+)-Z--")


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
				detectiond['id'] = a_title['id']
				detectiond['data'] = {
							'UID': a_content['uid'],
							'date': a_content['date'],
							'ips': a_content['ips'],
							'ps': a_content['ps'],
							'ipd': a_content['ipd'],
							'pd': a_content['pd'],
							}
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

			f_respres = sectionf_resp.match(lines[0])
			f_resp = f_respres.groupdict()

			f_respallres = sectionf_resp_all.match(lines[0])
			f_respall = f_respallres.groupdict()

			detectiond['resp'] = { 'resp': f_resp['resp'] }
			detectiond['resp'].update(f_respall)

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
						detectiond['debug'] = h_mesgres.groupdict()
						detectiond['debug2'] = h_mesg
						detectiond['debug3'] = h_mesg['msgdata']

					except:
						print "h_mesg : %s " % h_mesg
						pass
					
					try:
						h_mesg['msgdata'] = re.sub('\] \[',']_-_[',h_mesg['msgdata'])
						h_mesg_params_array = h_mesg['msgdata'].split('_-_')
					except:
						print "h_mesg['msgdata'] : %s " % h_mesg['msgdata']
						pass


				#	del h_mesg['msgdata']
					h_mesg['msgdata'] = {}
#					h_mesg.update({ 'msgdata' : {} })
					

					for h_mesg_params in h_mesg_params_array:
						h_mesg_paramsres = sectionh_messages_params.match(h_mesg_params)
						h_mesg_params = h_mesg_paramsres.groupdict()
						if h_mesg_params['msgparam'] in h_mesg['msgdata']:
							if type(h_mesg['msgdata'][h_mesg_params['msgparam']]) is list:
								h_mesg['msgdata'][h_mesg_params['msgparam']].append(h_mesg_params['msgvalue'])
							else:
								speciallist = h_mesg['msgdata'][h_mesg_params['msgparam']].split()
								h_mesg['msgdata'][h_mesg_params['msgparam']] = speciallist
						else:
							h_mesg['msgdata'].update({ h_mesg_params['msgparam'] : h_mesg_params['msgvalue'] })

					detectiond['debug4'] = h_mesg
					listmesg.append(h_mesg)
					listmesg.append(h_mesg['msgdata'])
					detectiond['ModSec'].update({ 'list_mesg' : listmesg})
					del h_mesg['msgdata']
				else:
					detectiond['ModSec'].update({h_line['specialheader'] : h_line['specialvalue']})
				detectiond['ModSec'].update(h_mesg)
			continue
		if sectionz.match(section):
			detectionl.append(detectiond)
			continue
		if detectiond <> {}:
			detectionl.append(detectiond)

print len(detectionl)
##print "\n\n\n"
index = int(sys.argv[2])
print attaques[index]
#print sections
pprint.pprint(detectionl[index])
