import socket
from dnslib import DNSError, DNSRecord
from datetime import datetime, timedelta
import pickle


GOOGLE = "8.8.8.8"

def create_connection(port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(("", port))
	return sock

def upload_cache(data):
	with open("data.pickle", "wb") as f:
		pickle.dump(data, f)

def load_cache():
	try:
		with open('data.pickle', 'rb') as f:
 			data = pickle.load(f)
	except FileNotFoundError:
		return {}
	return data

class Rec:
	def __init__(self, rr, create_time):
		self.resource_record = rr
		self.create_time = create_time

def get_response(dns_record, cache):
	key = (str(dns_record.q.qname).lower(), dns_record.q.qtype)
	if key in cache and cache[key]:
		reply = dns_record.reply()
		reply.rr = [p.resource_record for p in cache[key]]
		return reply

def check_cache(rec):
	return datetime.now() - rec.create_time > timedelta(seconds=rec.resource_record.ttl)

def add_record(dns_record, cache):
	if cache:
		cache_delta = 0
		for key, value in cache.items():
			old_length = len(value)
			cache[key] = set(rec for rec in value if not check_cache(rec))
			cache_delta += old_length - len(cache[key])
	for r in dns_record.rr + dns_record.auth + dns_record.ar:
		date_time = datetime.now()
		k = (str(r.rname).lower(), r.rtype)
		if k in cache:
			cache[k].add(Rec(r, date_time))
		else:
			cache[k] = {Rec(r, date_time)}

def run():
	cache = load_cache()
	sock = create_connection(53)
	while True:
		data, addr = sock.recvfrom(2048)
		try:
			dns_record = DNSRecord.parse(data)
		except DNSError:
			continue
		add_record(dns_record, cache)
		if not dns_record.header.qr:
			response = get_response(dns_record, cache)
			try:
				if response:
					response = response.pack()
				else:
					response = dns_record.send(GOOGLE)
					add_record(DNSRecord.parse(response), cache)
				sock.connect(addr)
				sock.sendall(response)
				sock.close()
				sock = create_connection(53)
			except:
				pass
		if cache:
			upload_cache(cache)



if __name__ == "__main__":
	print("ON")
	try:
		run()
	finally:
		print("OFF")

