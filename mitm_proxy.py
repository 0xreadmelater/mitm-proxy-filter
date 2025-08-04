import re
import socket
import socketserver
import select
from urllib.parse import urlparse
import logging
import random
from datetime import datetime, timezone, timedelta
from OpenSSL import crypto
import ssl
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# global variable
logging.basicConfig(filename='blocked_domains.log', level=logging.INFO)

CA_CERT_PATH = "/Users/stan/StSecretRootCA.pem"
CA_KEY_PATH = "/Users/stan/StSecretRootCA.key"

cert_cache = {}  # global certificate cache

def generate_cert_cached(hostname):
    if hostname in cert_cache:
        return cert_cache[hostname]
    cert, key = ProxyRequestHandler.generate_cert(hostname, CA_CERT_PATH, CA_KEY_PATH)
    cert_cache[hostname] = (cert, key)
    return cert, key

class ProxyRequestHandler(socketserver.BaseRequestHandler):

    @staticmethod
    def generate_cert(hostname, ca_cert_path, ca_key_path):
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            raise ValueError("Invalid hostname for cert")

        # Load CA certificate
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Load CA private key
        with open(ca_key_path, "rb") as f:
            ca_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

        # Generate a new private key for the leaf cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Subject and issuer names
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        issuer = ca_cert.subject

        # Certificate builder
        now_utc = datetime.now(timezone.utc)

        san_list = [
            x509.DNSName(hostname)
        ]
              
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(random.getrandbits(64))
            .not_valid_before(now_utc)
            .not_valid_after(now_utc + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
        )

        # Sign certificate with CA private key
        cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

        # Serialize to PEM format
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # to match OpenSSL format
            encryption_algorithm=serialization.NoEncryption()
        )

        return cert_pem, key_pem
            
    def log_request(self, domain, status_cd, source, action):
        now_utc = datetime.now(timezone.utc)
        timestamp = now_utc.isoformat().replace('+00:00', 'Z')
        client_ip, client_port = self.client_address

        log_entry = (
            f"{timestamp} DOMAIN={domain} "
            f"STATUS_CD={status_cd} "
            f"CLIENT_IP={client_ip} "
            f"CLIENT_PORT={client_port} "
            f"SOURCE={source} ACTION={action}"
        )
        logging.info(log_entry)

    def block_domain(self, destination_host):
        print("Block Domain function")
        print(f"Proxy Server: Access Denied to {destination_host}")

        response_body = "<html><body><h1>403 Forbidden</h1><p>Access to this site is denied.</p></body></html>"
        response = (
            "HTTP/1.1 403 Forbidden\r\n"
            f"Content-Length: {len(response_body)}\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n"
            "\r\n"
            + response_body
        ).encode("utf-8")

        client_sock, server_sock = socket.socketpair()
        try:
            server_sock.sendall(response)
            self.tunnel_data(self.request, client_sock)
        finally:
            client_sock.close()
            server_sock.close()

        self.log_request(destination_host, "403", "BLOCKLIST_DOMAIN","Blocked")

    def handle(self):
        BLOCKLIST_DOMAIN = {
            "example.com",
            "schmoogle.com",
            "malware.org",
            "mitm.it",
            "facebook.com",
            "www.facebook.com"
        }
        # self.request is the client socket

        try:
            request_data = self.request.recv(8192)
        except ConnectionResetError as e:
            print(f"Error : Client closed connection before sending data.{e}")
            return
            
        if not request_data:
            print("No request data..")
            return

        # 1. Parse the request to get the destination host and port.
        try:
            client_request = request_data.decode('utf-8')
            # print(f"Client request[0] received: {client_request[0:]}")
            
        except UnicodeDecodeError as e:
            print(f"UnicodeDecodeError - Could not decode request as UTF-8. Treating as binary data.{e}")
            client_request = ""
        
        request_lines = client_request.split('\r\n')
        request_line = request_lines[0]

        try:
            method, url, version = request_line.split()
        except ValueError:
            print(f"[ERROR] Malformed request line: {request_line}")
            self.request.close()
            return

        # CONNECT can be used for non-HTTPS targets too; wrapping with TLS only works for port 443.

        port = 0

        if (method.upper() == "CONNECT"): 
            # host, port_str = rsplit(':', 1) # to handle malformed or IPv6 CONNECT lines more robustly.
            host, port_str = url.split(':')          
            port = int(port_str)

        if port == 443:   # HTTPS Request
            print(f"\n*** Method is CONNECT and https {host} {port} ***")
            if not host:
                response = (
                    "HTTP/1.1 400 Bad Request\r\n\r\n"
                ).encode('utf-8')
                self.request.sendall(response)

                # Close connection
                self.request.close()
                return
                            
            tls_client_socket = None
            real_server_socket = None

            try:
                # Send the 200 Connection established response
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                # Dynamically generate cert for the domain
                cert_pem, key_pem = generate_cert_cached(host)

                # Start TLS with the client using the generated cert
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                
                # Create temporary files for the certificate and key
                cert_file_path = f"/tmp/{host}.crt"
                key_file_path = f"/tmp/{host}.key"
                
                with open(cert_file_path, "wb") as cert_file:
                    cert_file.write(cert_pem)
                with open(key_file_path, "wb") as key_file:
                    key_file.write(key_pem)

                context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)
                
                try:
                    tls_client_socket = context.wrap_socket(self.request, server_side=True)

                except ssl.SSLError as e:
                    print(f"SSL Error intercepting HTTPS for {host}: {e}")
                except Exception as e:
                    logging.exception(f"Error intercepting HTTPS for {host}: {e}")
                    try:
                        self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    except BrokenPipeError:
                        # Client disconnected; ignore
                        pass
                finally:
                    # Clean up temporary files
                    os.remove(cert_file_path)
                    os.remove(key_file_path)        

                # Check against block list and send message using tls
                if host in BLOCKLIST_DOMAIN:
                    print(f"BLOCKING HTTPS {host} ")
                    response_body = "<html><body><h1>403 Forbidden</h1><p>Access to this site is denied.</p></body></html>"
                    response = (
                        "HTTP/1.1 403 Forbidden\r\n"
                        f"Content-Length: {len(response_body)}\r\n"
                        "Content-Type: text/html\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        + response_body
                    ).encode("utf-8")

                    tls_client_socket.sendall(response)
                    tls_client_socket.close()

                    self.log_request(host, "403", "BLOCKLIST_DOMAIN","Blocked")
                    return
                else:
                    print(f"Host is allowed: {host} ")

                    real_server_socket = ssl.create_default_context().wrap_socket(
                        socket.create_connection((host, port)),
                        server_hostname=host
                    )
                    self.log_request(host, "200", "BROWSER","Connection Established")
                    self.tunnel_data(tls_client_socket, real_server_socket)

            except Exception as e:
                logging.exception(f"Error intercepting HTTPS for {host}: {e}")
            finally:
                if tls_client_socket:
                    tls_client_socket.close()
                if real_server_socket:
                    real_server_socket.close()
        else:
            # HTTP Request
            # Using urlparse, we can get the hostname, port, path
            parsed_url = urlparse(url)
            destination_host = parsed_url.hostname    
            destination_port = parsed_url.port or 80 
            destination_path = parsed_url.path or '/'

            if parsed_url.query:
                destination_path += '?' + parsed_url.query

            if not destination_host:
                self.request.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                # Close connection
                self.request.close()
                return

            # Check against block list
            if destination_host in BLOCKLIST_DOMAIN:
                self.block_domain(destination_host)
                # Close connection
                self.request.close()
                return
            
            else:
                self.log_request(destination_host, "200", "BROWSER","Connection Established")

            # Rebuild the request line
            rebuilt_request_lines = [f"{method} {destination_path} {version}"]
            print(f"Request to be sent for HTTP: {rebuilt_request_lines}")
            rebuilt_request_lines += request_lines[1:]  # preserve headers
            rebuilt_request = '\r\n'.join(rebuilt_request_lines) # + '\r\n\r\n'
            rebuilt_request_bytes = rebuilt_request.encode('utf-8')

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
                    forward_socket.connect((destination_host, destination_port))
                    forward_socket.sendall(rebuilt_request_bytes)
                    self.tunnel_data(self.request, forward_socket)
            except Exception as e:
                logging.exception(f"ProxyRequestHandler: Error: {e}")

    def tunnel_data(self, client_socket, server_socket):
        sockets = [client_socket, server_socket]
        timeout = 60 

        while True:
            try:
                # This waits until one of the sockets has data to be read
                readable, _, exceptional = select.select(sockets, [], sockets, timeout)
                if exceptional or not readable:
                    break

                for s in readable:
                    try:
                        data = s.recv(4096)

                        if not data:
                            print("Tunnel_data No more data. returning")
                            return

                        if s is client_socket:
                            print("Here in tunnel - Server socket received data)")
                            server_socket.sendall(data)
                        else:
                            print("Here in tunnel - Client socket received data)")
                            client_socket.sendall(data)

                    except Exception as e:
                        logging.exception(f"Error in Receiving data {e}")
                        return

            except Exception as e:
                logging.exception(f"Error in Readable sockets {e}")
                break
                
if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 8080
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((HOST, PORT), ProxyRequestHandler)
    print(f"[*] Starting browser-ready proxy on port {PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down the server.")
        server.shutdown()
        server.server_close()