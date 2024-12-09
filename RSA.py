import hashlib
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


def RSAencryption(message,public_key,n):
    if not isinstance(message, str): 
        message=str(message)
    encrypted_message = [pow(ord(char), public_key, n) for char in message]
    return encrypted_message

def RSAdecryption(encrypted_message,private_key,n):
    decrypted_message = ''.join(chr(pow(char, private_key, n)) for char in encrypted_message)
    return decrypted_message

class SHA256:
    def __init__(self):
        # Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        # Round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
            0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
            0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
    
    def _right_rotate(self, value, shift):
        """Right rotate a 32-bit value by a given shift."""
        return ((value >> shift) | (value << (32 - shift))) & 0xffffffff
    
    def _pad(self, message):
        """Pad the message to make its length a multiple of 512 bits."""
        message = bytearray(message, 'utf-8')
        message_len = len(message) * 8
        message.append(0x80)
        
        while (len(message) * 8) % 512 != 448:
            message.append(0x00)
        
        message += message_len.to_bytes(8, 'big')
        return message
    
    def _chunks(self, message, chunk_size):
        """Divide the message into chunks of fixed size."""
        for i in range(0, len(message), chunk_size):
            yield message[i:i + chunk_size]
    
    def _process_chunk(self, chunk):
        """Process a single 512-bit chunk."""
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i * 4:(i + 1) * 4], 'big')
        
        for i in range(16, 64):
            s0 = self._right_rotate(w[i - 15], 7) ^ self._right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self._right_rotate(w[i - 2], 17) ^ self._right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff
        
        a, b, c, d, e, f, g, h = self.h
        
        for i in range(64):
            s1 = self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + self.k[i] + w[i]) & 0xffffffff
            s0 = self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xffffffff
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff
        
        self.h = [
            (self.h[0] + a) & 0xffffffff,
            (self.h[1] + b) & 0xffffffff,
            (self.h[2] + c) & 0xffffffff,
            (self.h[3] + d) & 0xffffffff,
            (self.h[4] + e) & 0xffffffff,
            (self.h[5] + f) & 0xffffffff,
            (self.h[6] + g) & 0xffffffff,
            (self.h[7] + h) & 0xffffffff,
        ]
    
    def compute(self, message):
        """Compute the SHA-256 hash of the input message."""
        message = str(message)
        message = self._pad(message)
        for chunk in self._chunks(message, 64):
            self._process_chunk(chunk)

        message_digest = ''.join(f'{value:08x}' for value in self.h)
        return message_digest



#AES encryption

def aes_encrypt(data, key):
    # Pad data to make its size a multiple of 16 bytes (AES block size)
    padded_data = pad(data, AES.block_size)

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the data
    encrypted_data = cipher.encrypt(padded_data)

    # Convert encrypted data and key to base64 for JSON serialization
    encrypted_data_b64 = b64encode(encrypted_data).decode('utf-8')
    
    return encrypted_data_b64
    
def aes_decrypt(data, key):
    # Decode from base64
    encrypted_data = b64decode(data)
    key = b64decode(key)

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Unpad the decrypted data
    unpadded_data = unpad(decrypted_data, AES.block_size)

    return unpadded_data
