from typing import Dict, Optional
import hashlib
import random
import secrets
import time
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@dataclass
class SecureMessage:
    cid: int
    timestamp: int
    # HKDF
    salt: bytes
    # AES256GCM
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    # Signature of plaintext
    signature: bytes

    def _sign_bytes(self) -> bytes:
        return self.cid.to_bytes(8, 'big') + self.timestamp.to_bytes(8, 'big') + self.salt + self.nonce + self.tag + self.ciphertext

    def to_bytes(self) -> bytes:
        return self.signature + self.cid.to_bytes(8, 'big') + self.timestamp.to_bytes(8, 'big') + self.salt + self.nonce + self.tag + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes):
        signature = data[:64]
        cid = int.from_bytes(data[64:72], 'big')
        timestamp = int.from_bytes(data[72:80], 'big')
        salt = data[80:112]
        nonce = data[112:124]
        tag = data[124:140]
        ciphertext = data[140:]
        return cls(cid, timestamp, salt, ciphertext, nonce, tag, signature)


class SecureChannelClient:
    def __init__(self, our_private_sign_key: Ed25519PrivateKey, peer_public_sign_key: Ed25519PublicKey):
        self.private_sign_key = our_private_sign_key
        self.sign_key_hash = hashlib.sha256(self.private_sign_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
        self.peer_public_sign_key = peer_public_sign_key
        self.peer_sign_key_hash = hashlib.sha256(self.peer_public_sign_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
        self.handshake_private_key: Optional[X25519PrivateKey] = X25519PrivateKey.generate()
        self.shared_secret: bytes = b''
        self.connection_id: int = 0

    def reset(self):
        self.handshake_private_key = X25519PrivateKey.generate()
        self.shared_secret = b''
        self.connection_id = 0

    def get_handshake(self):
        if self.handshake_private_key is None:
           self.reset()

        public_key = self.handshake_private_key.public_key()
        public_key_transmit_bytes = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_sign_bytes = self.private_sign_key.sign(public_key_transmit_bytes)

        return public_key_transmit_bytes, public_key_sign_bytes

    def complete_handshake(self, peer_public_key_bytes: bytes, peer_public_key_sign_bytes: bytes, connection_id: int):
        if not self.handshake_private_key:
            raise ValueError('Handshake already completed')

        self.peer_public_sign_key.verify(peer_public_key_sign_bytes, peer_public_key_bytes + connection_id.to_bytes(8, 'big'))  # raise exception if invalid
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        self.shared_secret = self.handshake_private_key.exchange(peer_public_key)
        self.handshake_private_key = None
        self.connection_id = connection_id

    def ready(self) -> bool:
        return self.shared_secret != b''

    def encrypt(self, plaintext_bytes: bytes):
        if not self.shared_secret:
            raise ValueError('Handshake not completed')

        hkdf_salt_bytes = secrets.token_bytes(32)
        aes_key_bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=hkdf_salt_bytes,
            info=b"SecureChannelv1",
        ).derive(self.shared_secret)

        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(aes_key_bytes), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        # Add associated data
        encryptor.authenticate_additional_data(bytes.fromhex(self.sign_key_hash))
        ciphertext_bytes = encryptor.update(plaintext_bytes) + encryptor.finalize()

        message = SecureMessage(self.connection_id, int(time.time() * 1000), hkdf_salt_bytes, ciphertext_bytes, nonce, encryptor.tag, b'')
        message.signature = self.private_sign_key.sign(message._sign_bytes())
        return message

    def decrypt(self, message: SecureMessage):
        if not self.shared_secret:
            raise ValueError('Handshake not completed')

        self.peer_public_sign_key.verify(message.signature, message._sign_bytes()) # raise exception if invalid

        aes_key_bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=message.salt,
            info=b"SecureChannelv1",
        ).derive(self.shared_secret)
        cipher = Cipher(algorithms.AES(aes_key_bytes), modes.GCM(message.nonce, message.tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(bytes.fromhex(self.peer_sign_key_hash))

        plaintext_bytes = decryptor.update(message.ciphertext) + decryptor.finalize()
        return plaintext_bytes
