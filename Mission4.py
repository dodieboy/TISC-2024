from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import struct

# Helper functions
def pad(data):
    """Apply PKCS#7 padding to the data"""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def md5_checksum(data):
    """Generate MD5 checksum for given data"""
    return hashlib.md5(data).digest()

# File structure setup
signature = b"AGPAY"  # Signature
version = b"01"       # Version
encryption_key = get_random_bytes(32)  # 32-byte encryption key
reserved = get_random_bytes(10)  # Reserved 10 bytes
iv = get_random_bytes(16)        # 16-byte IV
footer_signature = b"ENDAGP"     # Footer signature

# Simulated card data
card_number = b"1234567812345678"  # 16 bytes card number
card_expiry_date = struct.pack("<I", int(1672531199))  # Example expiry date (unix timestamp)
balance = struct.pack(">Q", 313371337)  # Corrected 8-byte balance in big-endian format

# Decrypted data structure: card number (16 bytes) + 4-byte padding + balance (8 bytes)
corrected_decrypted_data = (
    card_number +  # 16 bytes
    b"\x00" * 4  +
    card_expiry_date +  # 8-byte padding
    balance      # Corrected 8-byte balance
)

# Padding the decrypted data to align with AES block size
padded_corrected_decrypted_data = pad(corrected_decrypted_data)

# Encrypt the corrected decrypted data with AES-CBC
cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
corrected_encrypted_data = cipher.encrypt(padded_corrected_decrypted_data)

# Compute the checksum (MD5 hash of IV + encrypted data)
checksum_data = iv + corrected_encrypted_data
checksum = md5_checksum(checksum_data)

# Build the final binary file content
file_content = (
    signature +
    version +
    encryption_key +
    reserved +
    iv +
    corrected_encrypted_data +
    footer_signature +
    checksum
)

# Save the file
with open("agpay_card_final_8byte_balance.bin", "wb") as f:
    f.write(file_content)

print("File generated: agpay_card_final_8byte_balance.bin")
