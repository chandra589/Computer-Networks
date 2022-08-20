import sys
import dns.query
import dns.message
import time
import datetime

#https://www.iana.org/domains/root/servers
def GetRootServerList():
	return ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

rdtype_vals = {
	'A': 1      ,
	'NS':2      ,
	'CNAME':5	,
	'MX':15		,
	'DS':43     ,
	'RRSIG': 46 ,
	'DNSKEY':48 ,
	'SOA':6
}

def OneLevelSearch(hostname, rdtype, dns_server):
	dns_messg = dns.message.make_query(hostname, rdtype)
	response = dns.query.udp(dns_messg, dns_server)
	return response

def resolver(hostname, rdtype, cnames):
	for root in GetRootServerList():
		try:
			response = OneLevelSearch(hostname, rdtype, root)
			if len(response.additional) == 0:
				continue
			while(len(response.answer)==0 ):
				if len(response.additional) > 0:
					for rrset in response.additional:
						next_ip = rrset[0].address
						try:
							response2 = OneLevelSearch(hostname, rdtype, next_ip)
							response = response2
							break
						except Exception as e:
							pass
				else:
					if (len(response.authority) == 0):
						continue
					rrsets = response.authority[0]
					for rrset in rrsets:
						if (rrset.rdtype == rdtype_vals['SOA']):
							sys.exit()
						Aut_name = rrset.target
						ns_Autname = Aut_name.to_text()
						response2 = resolver(ns_Autname, 'A', cnames)
						response = response2
						authIPadd = response.answer[0].to_text()
						ip_add = response.answer[0].items
						AuthSer_IP = (list(response.answer[0].items.keys())[0]).address
						response = OneLevelSearch(hostname, rdtype, AuthSer_IP)
						return response
			if ((response.answer[0].rdtype == rdtype_vals[rdtype]) or response.answer[0].rdtype == rdtype_vals['MX']):
				return response
			elif(response.answer[0].rdtype == rdtype_vals['CNAME']):
				cname = ''
				for rrset in response.answer:
					for item in rrset.items:
						if (item.rdtype == rdtype_vals['CNAME']):
							cname = item.to_text()
							cnames.append(cname)
				if (rdtype == 'A'):
					finalresponse = resolver(cname, rdtype, cnames)
					return finalresponse
				else:
					return
			break
		except Exception as e: print(e)


if __name__ == '__main__':

	if len(sys.argv) == 3:
		#hostname = "www.google.com"
		#rdtype = "NS"
		hostname = sys.argv[1]
		rdtype = sys.argv[2]
		cnames = []
		print('QUESTION SECTION:\n')
		print(hostname + '     '+ rdtype+'\n')
		start_time = time.time()
		result = resolver(hostname, rdtype, cnames)
		time_taken = time.time() - start_time

		print('ANSWER SECTION:\n')
		for c in cnames:
			print(hostname + '   ' +'CNAME'+'     '+c)
		if not (result == None):
			if not (result.answer == None):
				allvals = result.answer[0].items
				for key in allvals.keys():
					print(hostname +'      '+rdtype+'	'+key.to_text())
			elif not(result.authority == None):
				allvals = result.authority[0].items
				for key in allvals.keys():
					print(hostname +'       '+rdtype+'   '+key.to_text())

		print('Query time: ' + str(int(time_taken * 1000)) + ' msec')
		print('WHEN:', datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
		print("MSG SIZE rcvd:",sys.getsizeof(result))
