import os
import sys
import base64
import json
import argparse
import socket
import ssl
import hashlib
import logging
import getpass
from datetime import datetime
from typing import Dict, Tuple, Optional, List, Union, Any

# Import cryptography libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("securetransfer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecureTransfer")

# Constants
BUFFER_SIZE = 4096
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # 256 bits
DEFAULT_PORT = 8443

class CryptoUtils:
    """Utility class for cryptographic operations."""
    
    @staticmethod
    def generate_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate an RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def save_key_pair(private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey, 
                     private_path: str, public_path: str) -> None:
        """Save RSA key pair to files."""
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(private_path, "wb") as f:
            f.write(private_pem)
        
        with open(public_path, "wb") as f:
            f.write(public_pem)
        
        # Set appropriate permissions for private key
        os.chmod(private_path, 0o600)
    
    @staticmethod
    def load_private_key(path: str) -> rsa.RSAPrivateKey:
        """Load RSA private key from file."""
        with open(path, "rb") as f:
            private_key_data = f.read()
            return load_pem_private_key(private_key_data, password=None)
    
    @staticmethod
    def load_public_key(path: str) -> rsa.RSAPublicKey:
        """Load RSA public key from file."""
        with open(path, "rb") as f:
            public_key_data = f.read()
            return load_pem_public_key(public_key_data)
    
    @staticmethod
    def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive a key from password using PBKDF2."""
        if salt is None:
            salt = os.urandom(SALT_SIZE)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=100000,
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate a random AES key."""
        return os.urandom(KEY_SIZE)
    
    @staticmethod
    def encrypt_with_rsa(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
        """Encrypt data using RSA public key."""
        return public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def decrypt_with_rsa(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """Decrypt data using RSA private key."""
        return private_key.decrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """Create digital signature for data."""
        return private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    @staticmethod
    def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
        """Verify digital signature."""
        try:
            public_key.verify(
                signature,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def encrypt_file(file_path: str, key: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Encrypt a file using AES-256-CBC.
        
        Args:
            file_path: Path to the file to encrypt
            key: Encryption key
            
        Returns:
            Tuple of (encrypted_data, iv, tag, file_hash)
        """
        # Generate a random IV
        iv = os.urandom(IV_SIZE)
        
        # Create encryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Create hasher for file integrity
        file_hasher = hashes.Hash(hashes.SHA256())
        
        # Create HMAC for authentication
        h = hmac.HMAC(key, hashes.SHA256())
        
        # Create PKCS7 padder
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        
        # Read file and encrypt
        with open(file_path, 'rb') as f:
            data = f.read()
            
        # Update hash
        file_hasher.update(data)
        
        # Pad data
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Update HMAC
        h.update(encrypted_data)
        
        # Calculate tag and file hash
        tag = h.finalize()
        file_hash = file_hasher.finalize()
        
        return encrypted_data, iv, tag, file_hash
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, iv: bytes, tag: bytes, key: bytes) -> bytes:
        """
        Decrypt data that was encrypted with AES-256-CBC.
        
        Args:
            encrypted_data: Encrypted data
            iv: Initialization vector
            tag: HMAC tag
            key: Decryption key
            
        Returns:
            Decrypted data
        """
        # Verify HMAC
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(encrypted_data)
        try:
            h.verify(tag)
        except Exception:
            logger.error("HMAC verification failed - data may have been tampered with!")
            raise ValueError("Data integrity check failed")
        
        # Create decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Create unpadder
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        
        # Decrypt data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        try:
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        except Exception as e:
            logger.error(f"Padding error during decryption: {e}")
            raise ValueError("Decryption failed")
        
        return unpadded_data


class SecureTransferProtocol:
    """Protocol for secure file transfer."""
    
    @staticmethod
    def create_ssl_context(server_side: bool, cert_file: str, key_file: str) -> ssl.SSLContext:
        """Create an SSL context for secure connections."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if server_side else ssl.Purpose.SERVER_AUTH)
        context.check_hostname = not server_side
        context.verify_mode = ssl.CERT_REQUIRED
        
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        
        # Set strong ciphers
        context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
        
        # Set minimum TLS version
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return context
    
    @staticmethod
    def send_message(sock: ssl.SSLSocket, message: Dict) -> None:
        """Send a message over an SSL socket."""
        # Convert message to JSON
        data = json.dumps(message).encode('utf-8')
        
        # Send message length first
        length = len(data).to_bytes(4, byteorder='big')
        sock.sendall(length)
        
        # Send actual data
        sock.sendall(data)
    
    @staticmethod
    def receive_message(sock: ssl.SSLSocket) -> Dict:
        """Receive a message from an SSL socket."""
        # Receive message length
        length_bytes = sock.recv(4)
        if not length_bytes:
            raise ConnectionError("Connection closed")
        
        length = int.from_bytes(length_bytes, byteorder='big')
        
        # Receive data in chunks
        data = b''
        remaining = length
        while remaining > 0:
            chunk = sock.recv(min(BUFFER_SIZE, remaining))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
            remaining -= len(chunk)
        
        # Parse JSON message
        message = json.loads(data.decode('utf-8'))
        return message
    
    @staticmethod
    def send_file(sock: ssl.SSLSocket, file_path: str, receiver_public_key: rsa.RSAPublicKey, 
                 sender_private_key: rsa.RSAPrivateKey) -> Dict:
        """
        Send a file securely over an SSL socket.
        
        Args:
            sock: SSL socket
            file_path: Path to the file to send
            receiver_public_key: Receiver's public key for encryption
            sender_private_key: Sender's private key for signing
            
        Returns:
            Message containing transfer result
        """
        try:
            # Generate a random AES key for this file
            file_key = CryptoUtils.generate_aes_key()
            
            # Encrypt the file
            encrypted_data, iv, tag, file_hash = CryptoUtils.encrypt_file(file_path, file_key)
            
            # Encrypt the AES key with receiver's public key
            encrypted_key = CryptoUtils.encrypt_with_rsa(receiver_public_key, file_key)
            
            # Sign the file hash
            signature = CryptoUtils.sign_data(sender_private_key, file_hash)
            
            # Create file info message
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            file_info = {
                "type": "file_info",
                "filename": filename,
                "original_size": file_size,
                "encrypted_size": len(encrypted_data),
                "encrypted_key": base64.b64encode(encrypted_key).decode('ascii'),
                "iv": base64.b64encode(iv).decode('ascii'),
                "tag": base64.b64encode(tag).decode('ascii'),
                "hash": base64.b64encode(file_hash).decode('ascii'),
                "signature": base64.b64encode(signature).decode('ascii'),
                "timestamp": datetime.now().isoformat()
            }
            
            # Send file info
            SecureTransferProtocol.send_message(sock, file_info)
            
            # Receive acknowledgment
            response = SecureTransferProtocol.receive_message(sock)
            if response.get("type") != "ready_for_file":
                raise ValueError(f"Unexpected response: {response}")
            
            # Send file data
            sock.sendall(encrypted_data)
            
            # Wait for confirmation
            response = SecureTransferProtocol.receive_message(sock)
            if response.get("type") != "file_received":
                raise ValueError(f"Unexpected response: {response}")
            
            return response
        
        except Exception as e:
            logger.error(f"Error sending file: {e}", exc_info=True)
            raise
    
    @staticmethod
    def receive_file(sock: ssl.SSLSocket, save_dir: str, receiver_private_key: rsa.RSAPrivateKey, 
                    sender_public_key: rsa.RSAPublicKey) -> Dict:
        """
        Receive a file securely from an SSL socket.
        
        Args:
            sock: SSL socket
            save_dir: Directory to save the file
            receiver_private_key: Receiver's private key for decryption
            sender_public_key: Sender's public key for verification
            
        Returns:
            Message containing transfer result
        """
        try:
            # Receive file info
            file_info = SecureTransferProtocol.receive_message(sock)
            if file_info.get("type") != "file_info":
                raise ValueError(f"Unexpected message type: {file_info.get('type')}")
            
            # Extract file info
            filename = file_info["filename"]
            encrypted_size = file_info["encrypted_size"]
            encrypted_key = base64.b64decode(file_info["encrypted_key"])
            iv = base64.b64decode(file_info["iv"])
            tag = base64.b64decode(file_info["tag"])
            file_hash = base64.b64decode(file_info["hash"])
            signature = base64.b64decode(file_info["signature"])
            
            # Verify signature
            if not CryptoUtils.verify_signature(sender_public_key, file_hash, signature):
                raise ValueError("Invalid file signature - file may have been tampered with")
            
            # Decrypt the file key
            file_key = CryptoUtils.decrypt_with_rsa(receiver_private_key, encrypted_key)
            
            # Send ready signal
            SecureTransferProtocol.send_message(sock, {"type": "ready_for_file"})
            
            # Receive encrypted file data
            encrypted_data = b''
            remaining = encrypted_size
            while remaining > 0:
                chunk = sock.recv(min(BUFFER_SIZE, remaining))
                if not chunk:
                    raise ConnectionError("Connection closed")
                encrypted_data += chunk
                remaining -= len(chunk)
            
            # Decrypt the file data
            decrypted_data = CryptoUtils.decrypt_data(encrypted_data, iv, tag, file_key)
            
            # Verify the file hash
            data_hasher = hashes.Hash(hashes.SHA256())
            data_hasher.update(decrypted_data)
            computed_hash = data_hasher.finalize()
            
            if computed_hash != file_hash:
                raise ValueError("File hash verification failed")
            
            # Save the file
            save_path = os.path.join(save_dir, filename)
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Send confirmation
            response = {
                "type": "file_received",
                "filename": filename,
                "size": len(decrypted_data),
                "status": "success",
                "saved_path": save_path,
                "timestamp": datetime.now().isoformat()
            }
            SecureTransferProtocol.send_message(sock, response)
            
            return response
        
        except Exception as e:
            logger.error(f"Error receiving file: {e}", exc_info=True)
            error_response = {
                "type": "file_received",
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            try:
                SecureTransferProtocol.send_message(sock, error_response)
            except:
                pass
            raise


class SecureTransferServer:
    """Server for secure file transfer."""
    
    def __init__(self, host: str, port: int, cert_file: str, key_file: str, 
                public_key_file: str, private_key_file: str, save_dir: str):
        """Initialize the server."""
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.public_key_file = public_key_file
        self.private_key_file = private_key_file
        self.save_dir = save_dir
        
        # Ensure save directory exists
        os.makedirs(save_dir, exist_ok=True)
        
        # Load keys
        self.private_key = CryptoUtils.load_private_key(private_key_file)
        self.public_key = CryptoUtils.load_public_key(public_key_file)
        
        # Create SSL context
        self.ssl_context = SecureTransferProtocol.create_ssl_context(
            server_side=True,
            cert_file=cert_file,
            key_file=key_file
        )
        
        logger.info(f"Server initialized with host={host}, port={port}")
    
    def start(self) -> None:
        """Start the server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            logger.info(f"Server started, listening on {self.host}:{self.port}")
            print(f"Server started, listening on {self.host}:{self.port}")
            
            try:
                while True:
                    client_socket, addr = server_socket.accept()
                    with self.ssl_context.wrap_socket(client_socket, server_side=True) as ssl_socket:
                        logger.info(f"Connection from {addr}")
                        self._handle_client(ssl_socket, addr)
            
            except KeyboardInterrupt:
                logger.info("Server shutdown requested")
                print("Server shutdown requested")
            
            except Exception as e:
                logger.error(f"Server error: {e}", exc_info=True)
                print(f"Server error: {e}")
    
    def _handle_client(self, ssl_socket: ssl.SSLSocket, addr: Tuple[str, int]) -> None:
        """Handle a client connection."""
        try:
            # Exchange public keys
            client_message = SecureTransferProtocol.receive_message(ssl_socket)
            
            if client_message.get("type") != "hello":
                raise ValueError(f"Unexpected message type: {client_message.get('type')}")
            
            # Get client's public key
            client_public_key_pem = base64.b64decode(client_message["public_key"])
            client_public_key = load_pem_public_key(client_public_key_pem)
            
            # Send our public key
            server_public_key_pem = self.public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            
            response = {
                "type": "hello_ack",
                "public_key": base64.b64encode(server_public_key_pem).decode('ascii'),
                "status": "ready"
            }
            SecureTransferProtocol.send_message(ssl_socket, response)
            
            # Process client request
            request = SecureTransferProtocol.receive_message(ssl_socket)
            
            if request.get("type") == "send_file":
                logger.info(f"Client {addr} wants to send a file")
                SecureTransferProtocol.receive_file(
                    sock=ssl_socket,
                    save_dir=self.save_dir,
                    receiver_private_key=self.private_key,
                    sender_public_key=client_public_key
                )
                logger.info(f"File received from {addr}")
            
            elif request.get("type") == "get_file":
                filename = request.get("filename")
                if not filename:
                    raise ValueError("No filename specified")
                
                file_path = os.path.join(self.save_dir, filename)
                if not os.path.exists(file_path):
                    raise FileNotFoundError(f"File {filename} not found")
                
                logger.info(f"Client {addr} requested file {filename}")
                SecureTransferProtocol.send_file(
                    sock=ssl_socket,
                    file_path=file_path,
                    receiver_public_key=client_public_key,
                    sender_private_key=self.private_key
                )
                logger.info(f"File {filename} sent to {addr}")
            
            elif request.get("type") == "list_files":
                files = os.listdir(self.save_dir)
                response = {
                    "type": "file_list",
                    "files": [
                        {
                            "name": f,
                            "size": os.path.getsize(os.path.join(self.save_dir, f)),
                            "modified": datetime.fromtimestamp(
                                os.path.getmtime(os.path.join(self.save_dir, f))
                            ).isoformat()
                        }
                        for f in files if os.path.isfile(os.path.join(self.save_dir, f))
                    ]
                }
                SecureTransferProtocol.send_message(ssl_socket, response)
                logger.info(f"Sent file list to {addr}")
            
            else:
                raise ValueError(f"Unsupported request type: {request.get('type')}")
        
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}", exc_info=True)
            try:
                error_response = {
                    "type": "error",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                SecureTransferProtocol.send_message(ssl_socket, error_response)
            except:
                pass
        
        finally:
            ssl_socket.close()
            logger.info(f"Connection with {addr} closed")


class SecureTransferClient:
    """Client for secure file transfer."""
    
    def __init__(self, server_host: str, server_port: int, cert_file: str, key_file: str, 
                public_key_file: str, private_key_file: str, server_cert_file: str):
        """Initialize the client."""
        self.server_host = server_host
        self.server_port = server_port
        self.cert_file = cert_file
        self.key_file = key_file
        self.public_key_file = public_key_file
        self.private_key_file = private_key_file
        self.server_cert_file = server_cert_file
        
        # Load keys
        self.private_key = CryptoUtils.load_private_key(private_key_file)
        self.public_key = CryptoUtils.load_public_key(public_key_file)
        
        # Create SSL context
        self.ssl_context = SecureTransferProtocol.create_ssl_context(
            server_side=False,
            cert_file=cert_file,
            key_file=key_file
        )
        
        # Load server's certificate for verification
        self.ssl_context.load_verify_locations(server_cert_file)
        
        logger.info(f"Client initialized with server={server_host}:{server_port}")
    
    def connect(self) -> ssl.SSLSocket:
        """Connect to the server and perform handshake."""
        # Create socket and wrap with SSL
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = self.ssl_context.wrap_socket(sock, server_hostname=self.server_host)
        
        # Connect to server
        ssl_sock.connect((self.server_host, self.server_port))
        logger.info(f"Connected to server {self.server_host}:{self.server_port}")
        
        # Send our public key
        public_key_pem = self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
        hello_message = {
            "type": "hello",
            "public_key": base64.b64encode(public_key_pem).decode('ascii')
        }
        SecureTransferProtocol.send_message(ssl_sock, hello_message)
        
        # Get server's public key
        response = SecureTransferProtocol.receive_message(ssl_sock)
        
        if response.get("type") != "hello_ack":
            raise ValueError(f"Unexpected response type: {response.get('type')}")
        
        if response.get("status") != "ready":
            raise ValueError(f"Server not ready: {response.get('status')}")
        
        # Parse server's public key
        server_public_key_pem = base64.b64decode(response["public_key"])
        self.server_public_key = load_pem_public_key(server_public_key_pem)
        
        return ssl_sock
    
    def send_file(self, file_path: str) -> Dict:
        """Send a file to the server."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found")
        
        try:
            with self.connect() as ssl_sock:
                # Request to send file
                request = {
                    "type": "send_file"
                }
                SecureTransferProtocol.send_message(ssl_sock, request)
                
                # Send the file
                result = SecureTransferProtocol.send_file(
                    sock=ssl_sock,
                    file_path=file_path,
                    receiver_public_key=self.server_public_key,
                    sender_private_key=self.private_key
                )
                
                return result
        
        except Exception as e:
            logger.error(f"Error sending file: {e}", exc_info=True)
            raise
    
    def get_file(self, filename: str, save_path: str) -> Dict:
        """Get a file from the server."""
        try:
            with self.connect() as ssl_sock:
                # Request file
                request = {
                    "type": "get_file",
                    "filename": filename
                }
                SecureTransferProtocol.send_message(ssl_sock, request)
                
                # Save directory
                save_dir = os.path.dirname(save_path)
                if save_dir:
                    os.makedirs(save_dir, exist_ok=True)
                
                # Receive the file
                result = SecureTransferProtocol.receive_file(
                    sock=ssl_sock,
                    save_dir=os.path.dirname(save_path) if os.path.dirname(save_path) else ".",
                    receiver_private_key=self.private_key,
                    sender_public_key=self.server_public_key
                )
                
                # Rename if necessary
                if os.path.basename(save_path) != filename:
                    os.rename(
                        os.path.join(os.path.dirname(save_path) if os.path.dirname(save_path) else ".", filename),
                        save_path
                    )
                    result["saved_path"] = save_path
                
                return result
        
        except Exception as e:
            logger.error(f"Error getting file: {e}", exc_info=True)
            raise
    
    def list_files(self) -> List[Dict]:
        """List files available on the server."""
        try:
            with self.connect() as ssl_sock:
                # Request file list
                request = {
                    "type": "list_files"
                }
                SecureTransferProtocol.send_message(ssl_sock, request)
                
                # Get response
                response = SecureTransferProtocol.receive_message(ssl_sock)
                
                if response.get("type") != "file_list":
                    raise ValueError(f"Unexpected response type: {response.get('type')}")
                
                return response.get("files", [])
        
        except Exception as e:
            logger.error(f"Error listing files: {e}", exc_info=True)
            raise


class CertificateManager:
    """Manages SSL certificates for secure connections."""
    
    @staticmethod
    def generate_self_signed_cert(organization: str, common_name: str, 
                                 cert_file: str, key_file: str) -> None:
        ""