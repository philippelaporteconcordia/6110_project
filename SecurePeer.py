#    securepeer.py
#
#    RSA+AES Hybrid Secure TCP channnel
#
#    Author: Philippe Laporte <philippe.laporte@mail.concordia.ca> 
#
#    Winter 2025 - Foundations of Cryptography
#
#    My first ever python program!
# 
#    In a Java-sense, all class fields are considered private, some may also be static, and all class methods are considered public
#
#    Run python securepeer.py -h for usage
#

import sys
import socket
import argparse
import logging
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature



#--------------------------------------
# SecurePeer abstract base class
# -------------------------------------    


class SecurePeer:
    """Abstract role for Secure Peer-to-Peer chat"""

    RSA_PUBLIC_EXPONENT = 65537
    RSA_KEY_SIZE = 4096            # bits   

    STRING_ENCODING = 'utf-8'

    MAX_CHAT_MESSAGE_SIZE = 10000  # bytes 


    def __init__(self, host, port, logger):
        self.host = host
        self.port = port

        self.logger = logger

        #generate key pair
        #logger.info('Generating RSA key pair with exponent ' + str(self.RSA_PUBLIC_EXPONENT) + ' and key size ' + str(self.RSA_KEY_SIZE) + ' bits')
        print('Generating RSA key pair with exponent', self.RSA_PUBLIC_EXPONENT, 'and key size', self.RSA_KEY_SIZE, 'bits')

        self.private_key = rsa.generate_private_key(
            public_exponent=self.RSA_PUBLIC_EXPONENT,
            key_size=self.RSA_KEY_SIZE
        )
             
        #private_key_pem = private_key.private_bytes(
        #    encoding=serialization.Encoding.PEM,
        #    format=serialization.PrivateFormat.TraditionalOpenSSL,
        #    encryption_algorithm=serialization.NoEncryption()
        #)

        #print('private_key_pem is', private_key_pem, 'and has length', len(private_key_pem))
            
        self.public_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )    

        #print('public_key_pem is', self.public_key_pem, 'and has length', len(self.public_key_pem))



#--------------------------------------
# Initiator
# -------------------------------------      


class Initiator(SecurePeer):
    """Initiator role for Secure Peer-to-Peer chat"""
   
    def connect_to_peer(self):
        print('Initiating conversation')

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print('Connecting to host', self.host, 'on port', self.port)
        self.client_socket.settimeout(10) # 10 seconds
        self.client_socket.connect((self.host, self.port))
        self.client_socket.settimeout(None)
        print('Connected')
        


    def establish_session(self):
        print('Sending public key')    

        self.client_socket.sendall(self.public_key_pem)

        print('Awaiting peer public key')

        peer_public_key_pem = self.client_socket.recv(self.RSA_KEY_SIZE)    # Key size is upper-bound on pem size

        print('Received peer public key')#, peer_public_key_pem)

        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem
        )

        print('Generating AES key')

        aes_key = Fernet.generate_key()
        #aes_key = base64.urlsafe_b64decode(aes_key)

        #print('Encrypting AES key', aes_key, 'which has length', len(aes_key))
        print('Encrypting AES key with peer\'s public key')

        aes_key_cipher_text = peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
                    
        #print('Encrypted AES key is', aes_key_cipher_text, 'and have length', len(aes_key_cipher_text))
        print('Generating Signature from AES key with private key')

        signature = self.private_key.sign(
            aes_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        #print('signature bytes are', signature, 'and have length', len(signature))

        print('Sending AES key with appended Signature')

        self.client_socket.sendall(aes_key_cipher_text + signature)

        print('Initiating AES session')

        #aes_key = base64.urlsafe_b64encode(aes_key)
        self.fernet = Fernet(aes_key)


    
    def have_conversation(self, next_message, on_peer_message):
        # TODO why no do-while loops in python?
        print('Awaiting MOTD\n')

        motd_cipher_text = self.client_socket.recv(self.MAX_CHAT_MESSAGE_SIZE)
        motd = self.fernet.decrypt(motd_cipher_text)
        on_peer_message(str(motd, self.STRING_ENCODING))
        message = next_message()

        while(message): # empty message ends conversation
            # send
            cipherMessage = self.fernet.encrypt(bytes(message, self.STRING_ENCODING))
            self.client_socket.sendall(cipherMessage)
                
            # receive
            cipherReply = self.client_socket.recv(self.MAX_CHAT_MESSAGE_SIZE)
            reply = self.fernet.decrypt(cipherReply)

            on_peer_message(str(reply, self.STRING_ENCODING))
            message = next_message()
            
        

    def shutdown(self):
        try:    
            self.client_socket.close()
        except AttributeError:
            pass


            

#--------------------------------------
# Responder
# -------------------------------------                              
   

class Responder(SecurePeer):
    """Responder role for Secure Peer-to-Peer chat"""


    MOTD =  'Welcome to our secure chat!'  


    def listen_for_peer_connection(self):
        print('Listening for incoming connections on port', self.port)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
       
            

    def await_peer_connection(self):
        print('Waiting for incoming conversation')

        self.client_socket, client_address  = self.server_socket.accept()

        print('Connected to initiator peer from host', client_address[0]) 
         
            

    def establish_session(self):
        try:
            peer_public_key_pem = self.client_socket.recv(self.RSA_KEY_SIZE)    # Key size is upper-bound on pem size

            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem
            )

            print('Received peer public key')
            #print('Got peer public key', peer_public_key_pem, 'which has length', len(peer_public_key_pem))

            print('Sending public key')  

            self.client_socket.sendall(self.public_key_pem)

            print('Waiting for AES key')

            aes_key_cipher_payload = self.client_socket.recv(self.RSA_KEY_SIZE // 4)

            #print('size of received payload is', len(aes_key_cipher_payload))

            cipher_payload_part_size = self.RSA_KEY_SIZE // 4 // 2

            #print('size of cipher_payload_part_size is', cipher_payload_part_size)

            aes_key_cipher_text = aes_key_cipher_payload[:cipher_payload_part_size]
            signature = aes_key_cipher_payload[cipher_payload_part_size:]

            print('Received AES key and signature')
            #print('Got AES key bytes', aes_key_cipher_text, 'which has length', len(aes_key_cipher_text))
            #print('Got signature', signature, 'which has length', len(signature))

            print('Decrypting AES key using private key')

            aes_key = self.private_key.decrypt(
                aes_key_cipher_text,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        
            print('Verifying signature using peer public key')

            peer_public_key.verify(
                signature,
                aes_key,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            #aes_key = base64.urlsafe_b64encode(aes_key)
            self.fernet = Fernet(aes_key)

        except InvalidSignature as e:
            print ("Invalid signature for AES key message")
            raise e
        except Exception as e:
            print(e)
            raise e
             


    def have_conversation(self, next_message, on_peer_message):
        print('Sending MOTD\n')

        message = self.MOTD

        while(message):  # empty message ends conversation
            # send
            cipherMessage = self.fernet.encrypt(bytes(message, self.STRING_ENCODING))
            self.client_socket.sendall(cipherMessage)
  
            # receive    
            cipherReply = self.client_socket.recv(self.MAX_CHAT_MESSAGE_SIZE)
            reply = self.fernet.decrypt(cipherReply)
                    
            on_peer_message(str(reply, self.STRING_ENCODING))
            message = next_message()



    def shutdown_client(self):
        try:    
            self.client_socket.close()
        except AttributeError:
            pass    


    def shutdown(self):  
        print('Shutting down') 

        self.shutdown_client()
        self.server_socket.close()       
            
            


#--------------------------------------
# Main drivers
# -------------------------------------    


MESSAGE_PROMPT = '-> '


def initiator(host, port):
    try:
        logger = logging.getLogger(initiator.__name__)

        peer = Initiator(host, port, logger)
        peer.connect_to_peer()
        peer.establish_session()
        def next_message():
            return input(MESSAGE_PROMPT)
        def on_peer_message(message):
            print(message) 
        peer.have_conversation(next_message, on_peer_message) 
    except KeyboardInterrupt:
        sys.stderr.write('\r')  # eat the ^C 
    except Exception as e:
        print(e)
        #logger.info(e)
        pass
    finally:
        #logger.info('Ending conversation') 
        print('Ending conversation')
        try:      
            peer.shutdown()
        except UnboundLocalError:
            pass      



def responder(port):
    try:
        logger = logging.getLogger(responder.__name__)

        peer = Responder(socket.gethostbyname(socket.gethostname()), port, logger)
        peer.listen_for_peer_connection()
        def next_message():
            return input(MESSAGE_PROMPT)
        def on_peer_message(message):
            print(message)     
        while (True):
            try:
                peer.await_peer_connection()
                peer.establish_session()
                peer.have_conversation(next_message, on_peer_message)
            except Exception as e:
                print('Ending conversation')
            finally:
                peer.shutdown_client()
    except KeyboardInterrupt:
        sys.stderr.write('\r')  # eat the ^C                             
    except Exception as e:
        print(e)    
    finally:
        try:      
            peer.shutdown()
        except UnboundLocalError:
            pass             



DEFAULT_CHAT_PORT = 7676


if __name__ == "__main__":
    # parse command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("role", help="specifies which role the peer is to play, either 'initiator' or 'responder'")
    parser.add_argument("--host", type=str, help="specifies which host the initiator is to connect to")
    parser.add_argument("--port", type=int, help="specifies which port the initiator is to connect to or the responder is to listen on. Default is " + str(DEFAULT_CHAT_PORT))
    args = parser.parse_args()

    #configure logging
    #file_handler = logging.FileHandler(filename=args.role + '.log')
    #stdout_handler = logging.StreamHandler(stream=sys.stdout)
    #logging.basicConfig(
    #    level=logging.INFO, 
    #    format='[%(asctime)s] {%(filename)s:%(funcName)s} %(levelname)s - %(message)s',
    #    handlers=[file_handler, stdout_handler]  
    #)

    if (args.role == 'initiator'):
        initiator(socket.gethostbyname(socket.gethostname()) if args.host is None else args.host, DEFAULT_CHAT_PORT if args.port is None else args.port)       
    elif (args.role == 'responder'): 
        # validate host
        if(args.host != None):
            print('Host ignored for responder role', file=sys.stderr)  # TODO send to stdout?
        responder(DEFAULT_CHAT_PORT if args.port is None else args.port)
    else:
        print('Unknown role, exiting', file=sys.stderr)       # TODO send to stdout?      