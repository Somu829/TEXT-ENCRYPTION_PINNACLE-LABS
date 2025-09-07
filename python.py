from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import rsa
import base64

def aes_encrypt(plain_text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())
    return base64.b64encode(nonce + ciphertext).decode(), key

def aes_decrypt(cipher_text_b64, key):
    data = base64.b64decode(cipher_text_b64.encode())
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext)
    return plain_text.decode()

def des_encrypt(plain_text):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = plain_text + ' ' * (8 - len(plain_text) % 8)
    ciphertext = cipher.encrypt(padded_text.encode())
    return base64.b64encode(ciphertext).decode(), key

def des_decrypt(cipher_text_b64, key):
    data = base64.b64decode(cipher_text_b64.encode())
    cipher = DES.new(key, DES.MODE_ECB)
    plain_text = cipher.decrypt(data)
    return plain_text.decode().strip()

def rsa_encrypt(plain_text):
    (pub_key, priv_key) = rsa.newkeys(512)
    cipher_text = rsa.encrypt(plain_text.encode(), pub_key)
    return base64.b64encode(cipher_text).decode(), priv_key

def rsa_decrypt(cipher_text_b64, priv_key):
    cipher_text = base64.b64decode(cipher_text_b64.encode())
    plain_text = rsa.decrypt(cipher_text, priv_key)
    return plain_text.decode()

if __name__ == "__main__":
    text = input("Enter text to encrypt: ")

    print("\n--- AES Encryption ---")
    aes_cipher, aes_key = aes_encrypt(text)
    print("Encrypted:", aes_cipher)
    print("Decrypted:", aes_decrypt(aes_cipher, aes_key))

    print("\n--- DES Encryption ---")
    des_cipher, des_key = des_encrypt(text)
    print("Encrypted:", des_cipher)
    print("Decrypted:", des_decrypt(des_cipher, des_key))

    print("\n--- RSA Encryption ---")
    rsa_cipher, rsa_private = rsa_encrypt(text)
    print("Encrypted:", rsa_cipher)
    print("Decrypted:", rsa_decrypt(rsa_cipher, rsa_private))
