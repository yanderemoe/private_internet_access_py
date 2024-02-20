#!/usr/bin/env python3
import json, requests, socket, os, random, subprocess

class PIA:
	dns = {}
	
	def generate_wg_private_and_public_key(private_key = ''):
		if private_key == '':
			private_key = os.popen('wg genkey').read().strip()
		public_key = os.popen(f'echo "{private_key}" | wg pubkey').read().strip()
		return private_key, public_key
	
	def getaddrinfo_handler(*args):
		if args[0] in PIA.dns:
			return PIA.dns[args[0]]
		return socket._getaddrinfo(*args)
	
	def patch_dns():
		if not hasattr(socket, '_getaddrinfo'):
			socket._getaddrinfo = socket.getaddrinfo
		socket.getaddrinfo = PIA.getaddrinfo_handler
	
	def add_patch_dns_record(hostname, ip, port):
		PIA.dns[hostname] = [(socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_STREAM, 6, '', (ip, port))]
	
	def unpatch_dns():
		socket.getaddrinfo = socket._getaddrinfo
	
	def __init__(self, username, password):
		self.servers = {}
		self.username = username
		self.password = password
		for server in self._get_servers():
			if 'meta' not in server['servers']:
				continue
			meta_ip = server['servers']['meta'][0]['ip']
			meta_cn = server['servers']['meta'][0]['cn']
			self.servers[meta_ip] = {
				'country_code': server['country'],
				'country_name': server['name'],
				'geo': server['geo'],
				'dns': server['dns'],
				'common_name': meta_cn,
				'servers': server['servers']
			}
			PIA.add_patch_dns_record(meta_cn, meta_ip, 443)
		
	def _get_servers(self):
		return json.loads(requests.get(
			url = 'https://serverlist.piaservers.net/vpninfo/servers/v4',
			timeout = 5
		).text.split('\n')[0].strip())['regions']
	
	def get_servers(self):
		return self.servers
	
	def get_servers_by_ip(self, ip):
		return self.servers[ip] if (ip in self.servers) else None	
	
	def get_servers_by_cn(self, cn):
		for server in self.servers:
			server = self.servers[server]
			if server['common_name'] == cn:
				return server
		return None

	def get_servers_by_country_code(self, country_name):
		return [self.servers[server_meta_ip] for server_meta_ip in self.servers if ('wg' in self.servers[server_meta_ip]['servers'] and ((self.servers[server_meta_ip]['country_code'] == country_name.upper()) or (self.servers[server_meta_ip]['country_name'].upper() == country_name.upper())))]
	
	def get_servers_by_prefix(self, prefix):
		servers = []
		for ip in self.servers:
			server = self.servers[ip]
			if not 'wg' in server['servers']:
				continue
			elif not server['servers']['wg'][0]['cn'].startswith(prefix):
				continue
			servers.append(server)
		return servers
	
	def get_token(self, hostname):
		response = requests.get(
			url = f'https://{self.username}:{self.password}@{hostname}/authv3/generateToken',
			verify = 'ca.rsa.4096.crt',
			timeout = 2
		).json()
		if response['status'] == 'OK':
			return response['token']
		return None
	
	def add_key(self, hostname, token, public_key):
		response = requests.post(
			url = f'https://{hostname}:1337/addKey',
			params = {
				'pt': token,
				'pubkey': public_key
			},
			verify = 'ca.rsa.4096.crt'
		).json()
		return response


def main():
	PIA.patch_dns()
	pia = PIA('****', '****')
	region = random.choice(['CA Vancouver'])
	server = random.choice(pia.get_servers_by_prefix(region) + pia.get_servers_by_country_code(region))
	token = pia.get_token(server['common_name'])
	wg = server['servers']['wg'][0]
	print('selected server', region, server, token)
	private_key, public_key = PIA.generate_wg_private_and_public_key()
	print(private_key, public_key)
	PIA.add_patch_dns_record(wg['cn'], wg['ip'], 1337)
	config = pia.add_key(wg['cn'], token, public_key)
	print(config)
	print('[Interface]\nAddress = {}\nPrivateKey = {}\nDNS = {}\n[Peer]\nPersistentKeepalive = 25\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {}\n'.format(
		config['peer_ip'],
		private_key,
		', '.join(config['dns_servers']),
		config['server_key'],
		'{}:{}'.format(config['server_ip'], config['server_port'])
	))
	
	PIA.unpatch_dns()

if __name__ == '__main__':
	main()
