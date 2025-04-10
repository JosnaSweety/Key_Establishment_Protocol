# Import required libraries
import os  # For file/folder operations
from cryptography.hazmat.primitives.asymmetric import rsa  # RSA key generation
from cryptography.hazmat.primitives import serialization, hashes  # Key serialization and hashing
from cryptography import x509  # X.509 certificate handling
from cryptography.x509.oid import NameOID  # For certificate subject names
from datetime import datetime, timedelta, timezone  # For certificate validity periods

# Create folders if they don't exist
# 'exist_ok=True' prevents errors if folders already exist
os.makedirs("Keys", exist_ok=True)  # Folder for private/public keys
os.makedirs("Certs", exist_ok=True)  # Folder for certificates

def generate_rsa_keypair():
    """
    Generates an RSA key pair (private + public key)
    Returns: Tuple of (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard RSA public exponent
        key_size=2048  # 2048-bit key for good security
    )
    return private_key, private_key.public_key()  # Return both keys

def save_private_key(key, filename):
    """
    Saves a private key to a PEM-encoded file
    Args:
        key: The private key to save
        filename: Output file path
    """
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,  # PEM format (Base64)
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # Traditional format
        encryption_algorithm=serialization.NoEncryption()  # No password protection
    )
    with open(filename, 'wb') as f:  # 'wb' = write binary
        f.write(pem)  # Write the key data

def save_public_key(public_key, filename):
    """
    Saves a public key to a PEM-encoded file
    Args:
        public_key: The public key to save
        filename: Output file path
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard format
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def generate_self_signed_cert(name, public_key, private_key):
    """
    Creates a self-signed X.509 certificate
    Args:
        name: Common Name (CN) for the certificate
        public_key: The subject's public key
        private_key: The issuer's private key (self-signed)
    Returns: X.509 certificate object
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name)  # Set CN=name
    ])
    
    # Certificate building with method chaining
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)  # Who the cert belongs to
        .issuer_name(subject)  # Self-signed (issuer = subject)
        .public_key(public_key)  # Bind public key
        .serial_number(x509.random_serial_number())  # Unique serial
        .not_valid_before(datetime.now(timezone.utc))  # Valid from now
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))  # 1 year validity
        .sign(private_key, hashes.SHA256())  # Sign with SHA-256
    )
    return cert

def save_certificate(cert, filename):
    """
    Saves an X.509 certificate to a PEM file
    Args:
        cert: Certificate object
        filename: Output file path
    """
    with open(filename, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def generate_all():
    """
    Main function that generates all keys and certificates
    for entities A, B, C, and the Server (S)
    """
    for name in ['A', 'B', 'C', 'S']:  # For each entity
        print(f"\n Generating keys and cert for {name}...")
        
        # Step 1: Generate key pair
        priv_key, pub_key = generate_rsa_keypair()
        
        # Step 2: Save keys
        save_private_key(priv_key, f"Keys/{name}_priv.pem")
        save_public_key(pub_key, f"Keys/{name}_pub.pem")
        
        # Step 3: Create and save certificate
        cert = generate_self_signed_cert(name, pub_key, priv_key)
        save_certificate(cert, f"Certs/cert_{name}.pem")
    
    print("\n All keys and certificates have been generated successfully!")

# Standard Python idiom to check if this script is run directly
if __name__ == "__main__":
    generate_all()  # Execute the main function

from cryptography.hazmat.primitives.serialization import load_pem_private_key
with open("Keys/A_priv.pem", "rb") as f:
    print(load_pem_private_key(f.read(), password=None))  # Should work
