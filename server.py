import http.server
import ssl
import os
import subprocess
import sys

PORT = 8443
FOLDER = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(FOLDER, 'cert.pem')
KEY_FILE = os.path.join(FOLDER, 'key.pem')

# Generate self-signed cert if not exists
if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
    print("Generating self-signed certificate...")
    try:
        subprocess.run([
            sys.executable, '-c',
            '''
import ssl, os
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime, ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")])
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv4Address("192.168.1.10")),
        ]), critical=False)
        .sign(key, hashes.SHA256(), default_backend()))

    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    print("Certificate generated!")
except ImportError:
    print("cryptography not found, using openssl...")
    import subprocess
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", "key.pem", "-out", "cert.pem", "-days", "3650",
        "-nodes", "-subj", "/CN=localhost"], check=True)
    print("Certificate generated via openssl!")
'''
        ], cwd=FOLDER, check=True)
    except Exception as e:
        print(f"Error generating cert: {e}")
        print("Please run: pip install cryptography")
        sys.exit(1)

os.chdir(FOLDER)

handler = http.server.SimpleHTTPRequestHandler

httpd = http.server.HTTPServer(('0.0.0.0', PORT), handler)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT_FILE, KEY_FILE)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

print(f"""
╔══════════════════════════════════════════╗
║       BlockDocs HTTPS Server             ║
╠══════════════════════════════════════════╣
║  PC:    https://localhost:{PORT}           ║
║  Phone: https://192.168.1.10:{PORT}       ║
╚══════════════════════════════════════════╝

⚠  First time: Browser will show "Not Secure" warning
   Click Advanced → Proceed to localhost (unsafe)
   Do this on BOTH PC and Phone!

Press Ctrl+C to stop.
""")

httpd.serve_forever()
