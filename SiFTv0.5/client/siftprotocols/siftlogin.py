#python3

import time
from rsa_utility import decrypt_message
import base64
import os
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error


class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None 


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users


    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):

        login_req_str = login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password'] 
        return login_req_str.encode(self.coding)


    def parse_login_req(self, msg_payload):
        try:
            # Extract the client_random (last 16 bytes) from the payload
            # client_random = msg_payload[-4:]  # Last 16 bytes
            payload_body = msg_payload  # All bytes except the last 16

            # Decode the rest of the payload
            # Assuming the payload format:
            # Username:<encrypted_username_in_base64>
            # Password:<encrypted_password_in_base64>
            lines = payload_body.decode('utf-8').splitlines()
            username_line = lines[:6]  # Adjust to the appropriate number of lines
            password_line = lines[7:13]  # Adjust to the appropriate number of lines
            username = '\n'.join(username_line)
            password = '\n'.join(password_line)

            # Convert to dictionary
            login_req_struct = {
                'username': username,
                'password': password
                # 'client_random': client_random.hex()  # Convert to hex for easy debugging
            }

            return login_req_struct

        except (IndexError, UnicodeDecodeError, ValueError) as e:
            raise SiFT_LOGIN_Error(f"Failed to parse login request: {e}")


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):

        login_res_str = login_res_struct['request_hash'].hex() 
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        return login_res_struct



    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False


    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        login_req_struct = self.parse_login_req(msg_payload)
        print("yay lets see",login_req_struct)
        try:
            encrypted_username = base64.b64decode(login_req_struct['username'])
            with open('temp_encrypted_username.bin', 'w') as f:
                f.write(login_req_struct['username'])
            decrypt_message(
                privkeyfile='test_keypair.pem',
                input_file='temp_encrypted_username.bin',
                output_file='temp_decrypted_username.txt',
                passphrase="crysys"
                )
            with open('temp_decrypted_username.txt', 'r', encoding='utf-8') as f:
                username = f.read()
            os.remove('temp_encrypted_username.bin')
            os.remove('temp_decrypted_username.txt')
        except Exception as e:
            raise SiFT_LOGIN_Error(f"Username decryption error: {e}")

        # Decrypt the password
        try:
            encrypted_password = base64.b64decode(login_req_struct['password'])
            with open('temp_encrypted_password.bin', 'w') as f:
                f.write(login_req_struct['password'])
            decrypt_message(
                privkeyfile='test_keypair.pem',  # Adjust as needed
                input_file='temp_encrypted_password.bin',
                output_file='temp_decrypted_password.txt',
                passphrase="crysys"
            )
            with open('temp_decrypted_password.txt', 'rb') as f:
                password = f.read().decode('utf-8')
            os.remove('temp_encrypted_password.bin')
            os.remove('temp_decrypted_password.txt')
        except Exception as e:
            raise SiFT_LOGIN_Error(f"Failed to decrypt password: {e}")
        # checking username and password
        
        if username in self.server_users:
            if not self.check_password(password, self.server_users[username]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unkown user attempted to log in')

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # sending login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('User ' + username+ ' logged in')
        # DEBUG 

        return username


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):

        # building a login request
        login_req_struct = {}
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # # DEBUG 
        # if self.DEBUG:
        #     print('Incoming payload (' + str(len(msg_payload)) + '):')
        #     print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
        #     print('------------------------------------------')
        # # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)

        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

