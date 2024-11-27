#python3
import socket
import sys
from Crypto import Random
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from rsa_utility import encrypt_message
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		self.msg_hdr_ver = b'\x00\x05'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.tk = None
		self.final_transfer_key = None


	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):
		parsed_msg_hdr, i = {}, 0

		# Parse the protocol version (2 bytes)
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+2], i+2
		
		# Parse the message type (2 bytes)
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+2], i+2
		
		# Parse the message length (2 bytes)
		parsed_msg_hdr['len'], i = msg_hdr[i:i+2], i+2
		
		# Parse the sequence number (2 bytes)
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+2], i+2
		
		# Parse the random value (6 bytes)
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+6], i+6
		
		# Parse the reserved field (2 bytes)
		parsed_msg_hdr['rsv'], i = msg_hdr[i:i+2], i+2

		return parsed_msg_hdr

	def derive_transfer_key(self,client_random, server_random, tk):
		combined_random = client_random + server_random
		kdf = HKDF(
			algorithm=hashes.SHA256(),
			length=32,
			salt=None,  # Optional: add salt for additional security
			info=b"SiFT key derivation",
		)
		return kdf.derive(combined_random + tk)



	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received

	# 			# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):
		try:
			# Read the current state from the state file
			with open('rcvstate.txt', 'rt') as sf:
				rcvsqn = int(sf.readline()[len("sqn: "):], base=10)  # Extract sequence number

			# Receive the message header
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message header received')

		# Parse the message header
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		# Check protocol version
		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		# Check message type
		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		# Check if message length is valid
		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		# Ensure the received message is of the expected length
		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# DEBUG: Print received message details
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')

		if len(msg_body) != msg_len - self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message body received')

		# Parse the header fields
		header_version_field = msg_hdr[0:2]      # Protocol version (2 bytes)
		header_type_field = msg_hdr[2:4]         # Message type (2 bytes)
		header_length_field = msg_hdr[4:6]       # Message length (2 bytes)
		header_sqn_field = msg_hdr[6:8]          # Sequence number (2 bytes)
		header_rnd_field = msg_hdr[8:14]         # Random value (6 bytes)
		header_reserved_field = msg_hdr[14:16]   # Reserved field (2 bytes)

		# Ensure the header fields are correctly parsed
		parsed_header = {
			'ver': header_version_field,
			'typ': header_type_field,
			'len': header_length_field,
			'sqn': header_sqn_field,
			'rnd': header_rnd_field,
			'rsv': header_reserved_field
		}

		# Perform sequence number check
		expected_sqn = int.from_bytes(header_sqn_field, byteorder='big')
		if expected_sqn <= rcvsqn:
			raise SiFT_MTP_Error('Message sequence number is too old')

		# Decrypt the payload (AES-GCM using SQN|RND as nonce)
		authtag_length = 12  # Authentication tag length
		nonce = header_sqn_field + header_rnd_field  # SQN + RND as the nonce for AES-GCM

		if parsed_header['typ'] == self.type_login_res:
			key = self.tk  # Use the temporary key for login response
		else:
			key = self.final_transfer_key  # Use the final key for other messages

		AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
		AE.update(msg_hdr)  # Include header in the authenticated encryption

		# Extract the encrypted payload and authentication tag
		encrypted_payload = msg_body[:-authtag_length]
		authtag = msg_body[-authtag_length:]

		try:
			# Decrypt and verify the payload using the authentication tag
			print("the client key",key)
			payload = AE.decrypt_and_verify(encrypted_payload, authtag)
		except Exception as e:
			raise SiFT_MTP_Error('Decryption or authentication failed --> ' + str(e))

		# If the message type is login_res, extract the server_random and derive the final transfer key
		if parsed_header['typ'] == self.type_login_res:
			if len(payload) < 16:
				raise SiFT_MTP_Error('Payload too short to contain server_random')
			server_random = payload[-16:]  # Last 16 bytes of the payload
			self.final_transfer_key = self.derive_transfer_key(self.final_transfer_key, server_random, self.tk)
			payload = payload[:-16]  # Remove the server_random from the payload

		# Update the sequence number state
		rcvsqn = expected_sqn

		# Save the updated state (sequence number and key) back to the state file
		state = "sqn: " + str(rcvsqn) + '\n'
		print("we go all the way")
		with open('rcvstate.txt', 'wt') as sf:
			sf.write(state)

		return parsed_header['typ'], payload


	# # receives and parses message, returns msg_type and msg_payload
	# def receive_msg(self):
	# 	try:
	# 		# Read the current state from the state file
	# 		with open('rcvstate.txt', 'rt') as sf:
	# 			rcvsqn = int(sf.readline()[len("sqn: "):], base=10)  # Extract sequence number
				

	# 		# Receive the message header
	# 		msg_hdr = self.receive_bytes(self.size_msg_hdr)
	# 	except SiFT_MTP_Error as e:
	# 		raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

	# 	if len(msg_hdr) != self.size_msg_hdr:
	# 		raise SiFT_MTP_Error('Incomplete message header received')

	# 	# Parse the message header
	# 	parsed_msg_hdr = self.parse_msg_header(msg_hdr)

	# 	# Check protocol version
	# 	if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
	# 		raise SiFT_MTP_Error('Unsupported version found in message header')

	# 	# Check message type
	# 	if parsed_msg_hdr['typ'] not in self.msg_types:
	# 		raise SiFT_MTP_Error('Unknown message type found in message header')

	# 	# Check if message length is valid
	# 	msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

	# 	# Ensure the received message is of the expected length
	# 	try:
	# 		msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
	# 	except SiFT_MTP_Error as e:
	# 		raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

	# 	# DEBUG: Print received message details
	# 	if self.DEBUG:
	# 		print('MTP message received (' + str(msg_len) + '):')
	# 		print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
	# 		print('BDY (' + str(len(msg_body)) + '): ')
	# 		print(msg_body.hex())
	# 		print('------------------------------------------')
		
	# 	if len(msg_body) != msg_len - self.size_msg_hdr:
	# 		raise SiFT_MTP_Error('Incomplete message body received')

	# 	# Parse the header fields
	# 	header_version_field = msg_hdr[0:2]      # Protocol version (2 bytes)
	# 	header_type_field = msg_hdr[2:4]         # Message type (2 bytes)
	# 	header_length_field = msg_hdr[4:6]       # Message length (2 bytes)
	# 	header_sqn_field = msg_hdr[6:8]          # Sequence number (2 bytes)
	# 	header_rnd_field = msg_hdr[8:14]         # Random value (6 bytes)
	# 	header_reserved_field = msg_hdr[14:16]   # Reserved field (2 bytes)

	# 	# Ensure the header fields are correctly parsed
	# 	parsed_header = {
	# 		'ver': header_version_field,
	# 		'typ': header_type_field,
	# 		'len': header_length_field,
	# 		'sqn': header_sqn_field,
	# 		'rnd': header_rnd_field,
	# 		'rsv': header_reserved_field
	# 	}

	# 	# Perform sequence number check if required (adjust as per your protocol needs)
	# 	expected_sqn = int.from_bytes(header_sqn_field, byteorder='big')
	# 	if expected_sqn <= rcvsqn:
	# 		raise SiFT_MTP_Error('Message sequence number is too old')

	# 	# Decrypt the payload (AES-GCM using SQN|RND as nonce)
	# 	authtag_length = 12  # Authentication tag length (assuming 12 bytes as per the specification)
	# 	nonce = header_sqn_field + header_rnd_field  # SQN + RND as the nonce for AES-GCM
	# 	AE = AES.new(self.tk, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
	# 	AE.update(msg_hdr)  # Include header in the authenticated encryption

	# 	# Extract the encrypted payload and authentication tag
	# 	encrypted_payload = msg_body[:-authtag_length]
	# 	authtag = msg_body[-authtag_length:]

	# 	try:
	# 		# Decrypt and verify the payload using the authentication tag
	# 		payload = AE.decrypt_and_verify(encrypted_payload, authtag)
	# 	except Exception as e:
	# 		raise SiFT_MTP_Error('Decryption or authentication failed --> ' + str(e))

	# 	# Update the sequence number state
	# 	rcvsqn = expected_sqn

	# 	# Save the updated state (sequence number and key) back to the state file
	# 	state = "sqn: " + str(rcvsqn) + '\n'
	# 	with open('rcvstate.txt', 'wt') as sf:
	# 		sf.write(state)

	# 	return parsed_header['typ'], payload





	# # receives and parses message, returns msg_type and msg_payload
	# def receive_msg(self):

	# 	try:
	# 		msg_hdr = self.receive_bytes(self.size_msg_hdr)
	# 	except SiFT_MTP_Error as e:
	# 		raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

	# 	if len(msg_hdr) != self.size_msg_hdr: 
	# 		raise SiFT_MTP_Error('Incomplete message header received')
		
	# 	parsed_msg_hdr = self.parse_msg_header(msg_hdr)

	# 	if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
	# 		raise SiFT_MTP_Error('Unsupported version found in message header')

	# 	if parsed_msg_hdr['typ'] not in self.msg_types:
	# 		raise SiFT_MTP_Error('Unknown message type found in message header')

	# 	msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

	# 	try:
	# 		msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
	# 	except SiFT_MTP_Error as e:
	# 		raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

	# 	# DEBUG 
	# 	if self.DEBUG:
	# 		print('MTP message received (' + str(msg_len) + '):')
	# 		print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
	# 		print('BDY (' + str(len(msg_body)) + '): ')
	# 		print(msg_body.hex())
	# 		print('------------------------------------------')
	# 	# DEBUG 

	# 	if len(msg_body) != msg_len - self.size_msg_hdr: 
	# 		raise SiFT_MTP_Error('Incomplete message body reveived')

	# 	return parsed_msg_hdr['typ'], msg_body


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# # builds and sends message of a given type using the provided payload
	# def send_msg(self, msg_type, msg_payload):
		
	# 	# build message
	# 	msg_size = self.size_msg_hdr + len(msg_payload)
	# 	msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
	# 	msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len

	# 	# DEBUG 
	# 	if self.DEBUG:
	# 		print('MTP message to send (' + str(msg_size) + '):')
	# 		print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
	# 		print('BDY (' + str(len(msg_payload)) + '): ')
	# 		print(msg_payload.hex())
	# 		print('------------------------------------------')
	# 	# DEBUG 

	# 	# try to send
	# 	try:
	# 		self.send_bytes(msg_hdr + msg_payload)
	# 	except SiFT_MTP_Error as e:
	# 		raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

	def send_msg(self, msg_type, msg_payload):
		isLoginReq = msg_type == self.type_login_req

		# Generate a fresh temporary key (tk) if it's a login request
		if isLoginReq:
			self.tk = Random.get_random_bytes(32)

		# Select the key to use
		encryption_key = self.tk if isLoginReq else self.final_transfer_key

		# Add client_random to the payload
		  # 16-byte random value
		if isLoginReq:
			client_random = Random.get_random_bytes(16)
			print("the client random we add",client_random)
			self.final_transfer_key = client_random  # Assign client_random as the final transfer key
			msg_payload = msg_payload + client_random  # Prepend client_random to the payload

		# Read the current state from the state file
		with open('sndstate.txt', 'rt') as sf:
			sqn = int(sf.readline()[len("sqn: "):], base=10)  # Extract sequence number

		# Compute message components
		payload_length = len(msg_payload)
		authtag_length = 12  # Authentication tag length
		header_length = self.size_msg_hdr

		# Include the encrypted key length if it's a login request
		if isLoginReq:
			# Encrypt the username and write it to a file
			with open('plaintext_username.txt', 'wb') as f:
				f.write(self.tk)

			try:
				encrypt_message(
					pubkeyfile='test_pubkey.pem',  # Server's public key file
					plaintext_file='plaintext_username.txt',  # Username file
					output_file='encrypted_username.txt',  # Encrypted username file
					privkeyfile=None,  # No signing from client
					sign=False  # No signing
				)
			except Exception as e:
				print('Encryption Error for username:', str(e))
				sys.exit(1)

			# Read the encrypted username from the file
			with open('encrypted_username.txt', 'rb') as f:
				encrypted_key = f.read()

			# Add the length of the encrypted key to the message length
			encrypted_key_length = len(encrypted_key)
		else:
			encrypted_key = b''  # No encrypted key for non-login requests
			encrypted_key_length = 0

		# Compute the total message length
		msg_length = header_length + payload_length + authtag_length

		# Build header
		header_version_field = self.msg_hdr_ver  # Protocol version
		header_length_field = msg_length.to_bytes(2, byteorder='big')  # Total message length
		header_sqn_field = (sqn + 1).to_bytes(2, byteorder='big')  # Sequence number
		header_rnd_field = Random.get_random_bytes(6)  # 6-byte random value
		header_reserved_field = b'\x00\x00'  # Reserved field

		# Full header
		header = (
			header_version_field + msg_type + header_length_field +
			header_sqn_field + header_rnd_field + header_reserved_field
		)

		# Encrypt payload with AES-GCM
		print("heres the clients key", encryption_key)
		nonce = header_sqn_field + header_rnd_field  # SQN|RND as the nonce
		AE = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
		AE.update(header)  # Authenticated encryption includes the header
		encrypted_payload, authtag = AE.encrypt_and_digest(msg_payload)

		# Combine the header, encrypted payload, and authentication tag
		if isLoginReq:
			full_message = header + encrypted_payload + authtag + encrypted_key
		else:
			full_message = header + encrypted_payload + authtag

		# DEBUG
		if self.DEBUG:
			print('Full MTP message:')
			print(f'Header ({len(header)} bytes): {header.hex()}')
			print(f'Payload ({len(encrypted_payload)} bytes): {encrypted_payload}')
			print(f'AuthTag ({len(authtag)} bytes): {authtag.hex()}')
			if isLoginReq:
				print(f'Client Random ({len(client_random)} bytes): {client_random}')
				print(f'Encrypted Key ({len(encrypted_key)} bytes): {encrypted_key.hex()}')
			print('------------------------------------------')

		# Send the full message
		try:
			self.send_bytes(full_message)
		except Exception as e:
			raise SiFT_MTP_Error(f'Unable to send bytes --> {str(e)}')

		# Update state (increment sequence number)
		new_state = f"sqn: {sqn + 1}\n"
		with open('sndstate.txt', 'wt') as sf:
			sf.write(new_state)
