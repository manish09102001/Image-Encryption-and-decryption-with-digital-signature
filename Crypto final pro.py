from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

KEY_SIZE = 2048

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key):
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key():
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key():
    with open("public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def validate_password(password: str, user_name: str, reg_no: str):
    if user_name and user_name.lower().replace(" ", "") in password.lower():
        raise ValueError("Attack Detected: Name found in key")
    if reg_no and reg_no.lower().replace(" ", "") in password.lower():
        raise ValueError("Attack Detected: Reg number found in key")

def generate_key(password: str, salt: bytes, user_name: str, reg_no: str) -> bytes:
    validate_password(password, user_name, reg_no)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_image(input_file: str, output_file: str, password: str, user_name: str, reg_no: str):
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = generate_key(password, salt, user_name, reg_no)

    with open(input_file, "rb") as file:
        plaintext = file.read()

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    private_key = load_private_key()
    signature = private_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(output_file, "wb") as file:
        file.write(salt + iv + encryptor.tag + len(signature).to_bytes(4, 'big') + signature + ciphertext)

    print("Encryption & signing completed successfully.")

def decrypt_image(input_file: str, output_file: str, password: str):
    with open(input_file, "rb") as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:28]
    tag = data[28:44]
    sig_len = int.from_bytes(data[44:48], 'big')
    signature = data[48:48+sig_len]
    ciphertext = data[48+sig_len:]

    key = generate_key(password, salt, "", "")  # name/reg_no not checked during decryption
    public_key = load_public_key()

    try:
        public_key.verify(
            signature,
            ciphertext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception:
        print("Signature verification failed. File may have been tampered with.")
        return

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        with open(output_file, "wb") as file:
            file.write(plaintext)
        print("Decryption & signature verification successful.")
    except:
        print("Decryption failed: Wrong password or data corrupted.")

def main():
    print("===== Secure Image Encryption/Decryption with Digital Signatures =====")
    print("1. Generate RSA Keys")
    print("2. Encrypt an image")
    print("3. Decrypt an image")
    choice = input("Enter your choice (1, 2 or 3): ")

    if choice == "1":
        priv, pub = generate_rsa_keys()
        save_keys(priv, pub)
        print("RSA key pair generated and saved.")
    elif choice == "2":
        input_file = input("Enter the image filename to encrypt: ")
        output_file = input("Enter the output encrypted filename: ")
        password = input("Enter a password for encryption: ")
        user_name = input("Enter your name: ")
        reg_no = input("Enter your registration number: ")
        try:
            encrypt_image(input_file, output_file, password, user_name, reg_no)
        except ValueError as e:
            print(e)
    elif choice == "3":
        input_file = input("Enter the encrypted filename: ")
        output_file = input("Enter the output decrypted image filename: ")
        password = input("Enter the password for decryption: ")
        decrypt_image(input_file, output_file, password)
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()