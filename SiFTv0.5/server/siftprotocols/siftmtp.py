#python3
import socket
import sys
from Crypto import Random
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
from rsa_utility import encrypt_message
from rsa_utility import decrypt_message
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

			# receives and parses message, returns msg_type and msg_payload
	# receives and parses message, returns msg_type and msg_payload
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

		# If type_login_req, adjust the message length by removing RSA key length
		if parsed_msg_hdr['typ'] == self.type_login_req:
			rsa_key_length = 504  # Length of the RSA-encrypted key
			msg_len += rsa_key_length

			# # Update the header length field
			# msg_len= msg_len.to_bytes(2, byteorder='big')

		# Ensure the received message is of the expected length
		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		if len(msg_body) != msg_len - self.size_msg_hdr:
			raise SiFT_MTP_Error('Incomplete message body received')

		# Parse the header fields
		header_sqn_field = parsed_msg_hdr['sqn']
		header_rnd_field = parsed_msg_hdr['rnd']
		header_type_field = parsed_msg_hdr['typ']

		# Perform sequence number check
		expected_sqn = int.from_bytes(header_sqn_field, byteorder='big')
		if expected_sqn <= rcvsqn:
			raise SiFT_MTP_Error('Message sequence number is too old')

		if header_type_field == self.type_login_req:
			try:
				# Decrypt the RSA-encrypted key
				with open('temp_encrypted_key.bin', 'wb') as f:
					f.write(msg_body[-504:])  # Extract the RSA-encrypted key
				msg_body = msg_body[:-504]

				decrypt_message(
					privkeyfile='test_keypair.pem',
					input_file='temp_encrypted_key.bin',
					output_file='temp_decrypted_key.txt',
					passphrase="crysys"
				)

				with open('temp_decrypted_key.txt', 'rb') as f:
					self.tk = f.read()
				key = self.tk

				# Cleanup temporary files
				os.remove('temp_encrypted_key.bin')
				os.remove('temp_decrypted_key.txt')
			except Exception as e:
				raise SiFT_MTP_Error(f"Key decryption or client_random handling error: {e}")
		else:
			key = self.final_transfer_key

		# Decrypt the payload (AES-GCM using SQN|RND as nonce)
		authtag_length = 12  # Authentication tag length
		nonce = header_sqn_field + header_rnd_field  # SQN + RND as the nonce for AES-GCM
		AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
		AE.update(msg_hdr)  # Include header in the authenticated encryption

		# Extract the encrypted payload and authentication tag
		encrypted_payload = msg_body[:-authtag_length]
		authtag = msg_body[-authtag_length:]

		try:
			# Decrypt and verify the payload using the authentication tag
			print("the server key",key)
			payload = AE.decrypt_and_verify(encrypted_payload, authtag)
		except Exception as e:
			print("we right here fam")
			raise SiFT_MTP_Error('Decryption or authentication failed --> ' + str(e))

		# Handle the login request message type
		if header_type_field == self.type_login_req:
			if len(payload) < 16:
				raise SiFT_MTP_Error('Payload too short to contain client_random')

			# Extract the client_random from the last 16 bytes of the decrypted payload
			client_random = payload[-16:]
			print("the server client cut", client_random)
			payload = payload[:-16]  # Remove the client_random from the payload

			# Store client_random as self.final_transfer_key for future use
			self.final_transfer_key = client_random

		# Update the sequence number state
		rcvsqn = expected_sqn

		# Save the updated state (sequence number) back to the state file
		state = f"sqn: {rcvsqn}\n"
		with open('rcvstate.txt', 'wt') as sf:
			sf.write(state)

		return header_type_field, payload


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
	# 	if parsed_header['typ'] == self.type_login_req:		
	# 		expected_sqn = int.from_bytes(header_sqn_field, byteorder='big')
	# 		if expected_sqn <= rcvsqn:
	# 			raise SiFT_MTP_Error('Message sequence number is too old')
			
	# 		try:
	# 			with open('temp_encrypted_username.bin', 'w') as f:
	# 				f.write((msg_body[-504:]).decode("utf-8"))
	# 			print("the encryted key from server:",msg_body[-504:])
	# 			msg_body = msg_body[:-504]
	# 			decrypt_message(
	# 				privkeyfile='test_keypair.pem',
	# 				input_file='temp_encrypted_username.bin',
	# 				output_file='temp_decrypted_username.txt',
	# 				passphrase="crysys"
	# 				)
	# 			print("we reach this far")
	# 			with open('temp_decrypted_username.txt', 'rb') as f:
	# 				self.tk = f.read()
	# 			os.remove('temp_encrypted_username.bin')
	# 			os.remove('temp_decrypted_username.txt')
	# 		except Exception as e:
	# 			raise SiFT_MTP_Error(f"Key descrioption Error: {e}")
	

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




	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	def derive_transfer_key(self, client_random, server_random, tk):
		combined_random = client_random + server_random
		kdf = HKDF(
			algorithm=hashes.SHA256(),
			length=32,
			salt=None,  # Optional: add salt for additional security
			info=b"SiFT key derivation",
		)
		return kdf.derive(combined_random + tk)


	def send_msg(self, msg_type, msg_payload):
		isLoginRes = msg_type == self.type_login_res

		# Read the current state from the state file
		with open('sndstate.txt', 'rt') as sf:
			sqn = int(sf.readline()[len("sqn: "):], base=10)  # Extract sequence number

		# Compute message components
		server_random = None
		if isLoginRes:
			server_random = get_random_bytes(16)  # Generate server_random for login response
			msg_payload += server_random  # Append server_random to the payload

		payload_length = len(msg_payload)
		authtag_length = 12  # Authentication tag length
		header_length = self.size_msg_hdr
		msg_length = header_length + payload_length + authtag_length

		# Build header
		header_version_field = self.msg_hdr_ver  # Protocol version
		header_length_field = msg_length.to_bytes(2, byteorder='big')  # Total message length
		header_sqn_field = (sqn + 1).to_bytes(2, byteorder='big')  # Sequence number
		header_rnd_field = get_random_bytes(6)  # 6-byte random value
		header_reserved_field = b'\x00\x00'  # Reserved field

		# Full header
		header = (header_version_field + msg_type + header_length_field +
				header_sqn_field + header_rnd_field + header_reserved_field)

		# Use appropriate key for encryption
		if isLoginRes:
			key = self.tk
			# Derive final transfer key for future use
			client_random = self.final_transfer_key  # Assumes client_random was stored here earlier
			self.final_transfer_key = self.derive_transfer_key(client_random, server_random, self.tk)
		else:
			key = self.final_transfer_key

		# Encrypt payload with AES-GCM
		nonce = header_sqn_field + header_rnd_field  # SQN|RND as the nonce
		AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
		AE.update(header)  # Authenticated encryption includes the header
		encrypted_payload, authtag = AE.encrypt_and_digest(msg_payload)

		# Combine the header, encrypted payload, and authentication tag
		full_message = header + encrypted_payload + authtag

		# DEBUG
		if self.DEBUG:
			print('Full MTP message:')
			print('HDR (' + str(len(header)) + '): ' + header.hex())
			print('Payload (' + str(len(encrypted_payload)) + '): ' + encrypted_payload.hex())
			print('AuthTag (' + str(len(authtag)) + '): ' + authtag.hex())
			print('------------------------------------------')

		# Send the full message
		try:
			self.send_bytes(full_message)
		except Exception as e:
			raise SiFT_MTP_Error('Unable to send bytes --> ' + str(e))

		# Update state (increment sequence number)
		new_state = f"sqn: {sqn + 1}\n"
		with open('sndstate.txt', 'wt') as sf:
			sf.write(new_state)





