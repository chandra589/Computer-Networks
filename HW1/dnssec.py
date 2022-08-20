import sys
import dns.query
import dns.message
import time
import datetime

#https://www.iana.org/domains/root/servers
def GetRootServerList():
	return ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

#Source from https://ftp.isc.org/isc/bind9/keys/9.11/bind.keys.v9_11
rootKey = [ dns.rrset.from_text('.',20326, 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=')]

rdtype_vals = {
	'A': 1      ,
	'NS':2      ,
	'CNAME':5	,
	'MX':15		,
	'DS':43     ,
	'RRSIG': 46 ,
	'DNSKEY':48 ,
}

# Get Top Level Domain IPs from root server

def OneLevelSearch(hostname, rdtype, dns_server, dnssec = True):
	dns_messg = dns.message.make_query(hostname, rdtype, want_dnssec=dnssec)
	response = dns.query.udp(dns_messg, dns_server)
	return response

def resolver_dnsec(hostname, rdtype, cnames):
	Verify_Success = True
	for root in GetRootServerList():
		if (Verify_Success == False):
			break
		prev_ds_rrset =''
		try:
			response = OneLevelSearch(hostname, rdtype, root)
			key_response = OneLevelSearch('.', 'DNSKEY', root)
			#root zone dnskey rrset verification
			rrsig = ''
			dnskey_rrset = ''
			rrset_name = ''
			try:
				for rrset in key_response.answer:
					if (rrset.rdtype == rdtype_vals['RRSIG']):
						rrsig = rrset
					elif(rrset.rdtype == rdtype_vals['DNSKEY']):
						dnskey_rrset = rrset
						rrset_name = dnskey_rrset.name
				if (rrsig == '' or dnskey_rrset == ''):
					print("ZONE -" + '  .  ' +'-----------'+ 'DNSSEC not supported')
					sys.exit()
				dns.dnssec.validate(dnskey_rrset, rrsig, {rrset_name: dnskey_rrset})
			except Exception as e: 
				print("ZONE -" + '  .  ' +'-----------'+ 'DNSKEY-RRSET Verification Failed')
				print('DNSSEC Verification Failed')
				sys.exit()
			print("ZONE -" + '  .  ' +'-----------'+ 'DNSKEY-RRSET Verified Successfully')
			try:
				rrsig = ''
				for rrset in response.authority:
					if (rrset.rdtype == rdtype_vals['RRSIG']):
						rrsig = rrset
					elif(rrset.rdtype == rdtype_vals['DS']):
						prev_ds_rrset = rrset
				if (rrsig == '' or prev_ds_rrset == ''):
					print("ZONE -" + '  .  ' +'-----------'+ 'DNSSEC not supported from this zone as we are not able to verify Zone DS record')
					sys.exit()
				dns.dnssec.validate(prev_ds_rrset, rrsig, {rrset_name: dnskey_rrset})
			except Exception as e:
				print("ZONE -" + '  .  ' +'-----------'+ 'DS-RRSET Verification Failed')
				print('DNSSEC Verification Failed')
				sys.exit()
			print("ZONE -" + '  .  ' +'-----------'+ 'DS-RRSET Verified Successfully')
			Root_ksk = ''
			for iter in dnskey_rrset.items:
				if (iter.flags == 257):
						Root_ksk = iter
						break
			publicrootkey = list(rootKey[0].items)[0]
			if (Root_ksk == ''):
				print("ZONE -" + '  .  ' +'-----------'+ 'DNSSEC not supported from this zone as we are not able to verify Zone KSK')
				sys.exit()
			if (Root_ksk.to_text() == publicrootkey.to_text()):
				print('ZONE -' '  .  '+'-----------'+ 'Root Key Signing Key Verified Successfully')
			
			if len(response.additional) == 0:
				continue
			while(Verify_Success):
				if(Verify_Success == False):
					break
				for rrset in response.additional:
					if (Verify_Success == False or (len(response.answer) > 0)):
						break
					if ((len(response.additional))>0):
						next_ip = rrset[0].address
						try:
							subdomain = response.authority[0].name.to_text()
							response_subdomain = OneLevelSearch(hostname, rdtype, next_ip)
							key_response_subdomain = OneLevelSearch(subdomain, 'DNSKEY', next_ip)
							response = response_subdomain
							if (len(key_response_subdomain.answer) == 0):
								break
							#first verify the dnskey_rrset
							rrsig = ''
							dnskey_rrset = ''
							rrset_name = ''
							try:
								for rrset in key_response_subdomain.answer:
									if (rrset.rdtype == rdtype_vals['RRSIG']):
										rrsig = rrset
									elif (rrset.rdtype == rdtype_vals['DNSKEY']):
										dnskey_rrset = rrset
										rrset_name = dnskey_rrset.name
								if (rrsig == '' or dnskey_rrset == ''):
									print("ZONE -" +' '+ subdomain + ' -----------'+ 'DNSSEC not supported from this zone as we are not able to verify Zone DSK RRSET')
									sys.exit()
								dns.dnssec.validate(dnskey_rrset, rrsig, {rrset_name: dnskey_rrset})
							except Exception as e:
								print("ZONE -" + ' ' + subdomain + ' -----------'+ 'DNSKEY-RRSET Verification Failed')
								print('DNSSEC Verification Failed')
								sys.exit()
							print("ZONE -" + ' ' + subdomain + ' -----------'+ 'DNSKEY-RRSET Verified Successfully')
							#second verify the dsrecord_rrset
							try:
								ds_rrset =''
								rrsig = ''
								for rrset in response_subdomain.authority:
									if (rrset.rdtype == rdtype_vals['RRSIG']):
										rrsig = rrset
									elif(rrset.rdtype == rdtype_vals['DS']):
										ds_rrset = rrset
								if (rrsig == '' or ds_rrset == ''):
									print("ZONE -" + ' ' + subdomain + ' -----------'+ 'DNSSEC not supported from this zone as we are not able to verify Zone DS record')
									sys.exit()
								dns.dnssec.validate(ds_rrset, rrsig, {rrset_name: dnskey_rrset})
							except Exception as e:
								print("ZONE -" + ' '+ subdomain+ ' -----------'+ 'DS-RRSET Verification Failed')
								print('DNSSEC Verification Failed')
								sys.exit()
							print("ZONE -" + ' '+ subdomain+ ' ------------'+ 'DS-RRSET Verified Successfully')
							#third verify the KSK from previous domain
							try:
								parent_hash = ((list(prev_ds_rrset.items))[0]).digest
								parent_hash_algo = ((list(prev_ds_rrset.items))[0]).digest_type
								hash_algo = ''; ksk_key = ''
								if (parent_hash_algo == 2):
									hash_algo = 'SHA256'
								else:
									hash_algo = 'SHA1'
								for iter in dnskey_rrset.items:
									if (iter.flags == 257):
										ksk_key = iter
										break
								if (ksk_key == ''):
									print("ZONE -" + ' '+ subdomain +' -----------'+ 'DNSSEC not supported from this zone as we are not able to verify Zone KSK')
									sys.exit()
								Hash_created = dns.dnssec.make_ds(rrset_name, ksk_key, hash_algo)
								if (parent_hash == Hash_created.digest):
									print("ZONE -" + ' '+ subdomain + ' ------------' + 'Zone Key Signing Key Verified Successfully')
									prev_ds_rrset = ds_rrset
								else:
									print("ZONE -" + ' ' + subdomain + ' ------------' + 'Zone Key Signing Key Verification Failed')
									print('DNSSEC Verification Failed')
									sys.exit()
							except Exception as e: print(e)
						except Exception as e:
							pass
					elif (len(response.authority) > 0):
						rrsets = response.authority[0]
						subdomain = response.authority[0].name.to_text()
						for rrset in rrsets:
							Aut_name = rrset.target
							ns_Autname = Aut_name.to_text()
							response2 = resolver(ns_Autname, 'A', cnames)
							response = response2
							authIPadd = response.answer[0].to_text()
							ip_add = response.answer[0].items
							AuthSer_IP = (list(response.answer[0].items.keys())[0]).address
							final_response = OneLevelSearch(hostname, rdtype, AuthSer_IP)
							final_key_response = OneLevelSearch(subdomain, 'DNSKEY', AuthSer_IP)
							#first verify the dnskey_rrset
							rrsig = ''
							dnskey_rrset = ''
							rrset_name = ''
							try:
								for rrset in final_key_response.answer:
									if (rrset.rdtype == rdtype_vals['RRSIG']):
										rrsig = rrset
									elif (rrset.rdtype == rdtype_vals['DNSKEY']):
										dnskey_rrset = rrset
										rrset_name = dnskey_rrset.name
								if (rrsig == '' or dnskey_rrset == ''):
									print("ZONE -" + ' ' +subdomain +' -----------'+ 'DNSSEC not supported from this zone as we are not able to verify Zone DSK RRSET')
									sys.exit()
								dns.dnssec.validate(dnskey_rrset, rrsig, {rrset_name: dnskey_rrset})
							except Exception as e:
								print("ZONE -" + ' ' +subdomain +' -----------'+ 'DNSKEY-RRSET Verification Failed')
								print('DNSSEC Verification Failed')
								sys.exit()
							print("ZONE -" + ' '+subdomain +' -----------'+ 'DNSKEY-RRSET Verified Successfully')
							#second verify the A-record_rrset
							try:
								A_rrset =''
								rrsig = ''
								for rrset in final_response.answer:
									if (rrset.rdtype == rdtype_vals['RRSIG']):
										rrsig = rrset
									elif(rrset.rdtype == rdtype_vals['A']):
										A_rrset = rrset
								if (A_rrset == '' or rrsig == ''):
									print("ZONE -" + ' '+ subdomain +' -----------'+ 'DNSSEC not supported from this zone as we are not able to verify Zone A record')
									sys.exit()
								dns.dnssec.validate(A_rrset, rrsig, {rrset_name: dnskey_rrset})
							except Exception as e:
								print("ZONE -" + ' '+subdomain +' -----------'+ 'A-record-RRSET Verification Failed')
								print('DNSSEC Verification Failed')
								sys.exit()
							print("ZONE -" + ' ' + subdomain +' -----------'+ 'A-record-RRSET Verified Successfully')
							#third verify the KSK from previous domain
							try:
								parent_hash = ((list(prev_ds_rrset.items))[0]).digest
								parent_hash_algo = ((list(prev_ds_rrset.items))[0]).digest_type
								hash_algo = ''; ksk_key = ''
								if (parent_hash_algo == 2):
									hash_algo = 'SHA256'
								else:
									hash_algo = 'SHA1'
								for iter in dnskey_rrset.items:
									if (iter.flags == 257):
										ksk_key = iter
										break
								if (ksk_key == ''):
									print("ZONE -" + ' '+subdomain +' -----------'+ 'DNSSEC not supported from this zone as we are not able to verify Zone KSK')
									sys.exit()
								Hash_created = dns.dnssec.make_ds(rrset_name, ksk_key, hash_algo)
								if (parent_hash == Hash_created.digest):
									print("ZONE -" + ' '+subdomain + ' ------------' + 'Zone Key Signing Key Verified Successfully')
									prev_ds_rrset = ds_rrset
									return final_response
								else:
									print("ZONE -" + ' '+subdomain + ' ------------' + 'Zone Key Signing Key Verification Failed')
									print('DNSSEC Verification Failed')
									sys.exit()
							except Exception as e: print(e)
			if ((len(response.answer)) > 0):
				if(response.answer[0].rdtype == rdtype_vals['CNAME']):
					cname = ''
					for rrset in response.answer:
						for item in rrset.items:
							if (item.rdtype == rdtype_vals['CNAME']):
								cname = item.to_text()
								cnames.append(cname)
					if (rdtype == 'A'):
						finalresponse = resolver_dnsec(cname, rdtype, cnames)
		except Exception as e:
			print(e)


def resolver(hostname, rdtype, cnames):
	for root in GetRootServerList():
		try:
			response = OneLevelSearch(hostname, rdtype, root, dnssec = False)
			if len(response.additional) == 0:
				continue
			while(len(response.answer)==0 ):
				if len(response.additional) > 0:
					for rrset in response.additional:
						next_ip = rrset[0].address
						try:
							response2 = OneLevelSearch(hostname, rdtype, next_ip, dnssec = False)
							response = response2
							break
						except Exception as e:
							pass  # print('Oops! Authoratative server timeout, try next one. ', e)
				else:             # if both ANSWER and ADDITIONAL is empty, then find the IP of AUTHORITY 
					if (len(response.authority) == 0):
						continue
					rrsets = response.authority[0]
					for rrset in rrsets:
						Aut_name = rrset.target
						ns_Autname = Aut_name.to_text()
						response2 = resolver(ns_Autname, 'A', cnames)
						response = response2
						authIPadd = response.answer[0].to_text()
						ip_add = response.answer[0].items
						AuthSer_IP = (list(response.answer[0].items.keys())[0]).address
						response = OneLevelSearch(hostname, rdtype, AuthSer_IP, dnssec = False)
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

	if len(sys.argv) == 2:
		hostname = "paypal.com"
		#hostname = sys.argv[1]
		rdtype = "A" #always checking for A record, please change it if required
		cnames = []
		print('QUESTION SECTION:\n')
		print(hostname + '     '+ rdtype+'\n')
		print('ANSWER SECTION:\n')
		result = resolver_dnsec(hostname, rdtype, cnames)
		for c in cnames:
			print(hostname + '   ' +'CNAME'+'     '+c)
		if not (result == None):
			if not (result.answer == None):
				allvals = result.answer[0].items
				for key in allvals.keys():
					print(hostname +'      '+rdtype+'	'+key.to_text())