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
    # X25519
    sender_ecc_key_hash: str
    receiver_ecc_key_hash: str
    # HKDF
    salt: bytes
    # AES256GCM
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    # timestamp
    timestamp: int
    # Signature of plaintext
    signature: bytes

    def to_bytes(self) -> bytes:
        return self.signature + bytes.fromhex(self.sender_ecc_key_hash) + bytes.fromhex(self.receiver_ecc_key_hash) + self.salt + self.nonce + self.tag + self.timestamp.to_bytes(4, "big") + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes):
        signature = data[:64]
        sender_ecc_key_hash = data[64:96].hex()
        receiver_ecc_key_hash = data[96:128].hex()
        salt = data[128:160]
        nonce = data[160:172]
        tag = data[172:188]
        timestamp = int.from_bytes(data[188:192], 'big')
        ciphertext = data[192:]
        return cls(sender_ecc_key_hash, receiver_ecc_key_hash, salt, ciphertext, nonce, tag, timestamp, signature)


class SecureChannel:
    def __init__(self, our_private_sign_key: Ed25519PrivateKey, peer_public_sign_key: Ed25519PublicKey):
        self.private_sign_key = our_private_sign_key
        self.sign_key_hash = hashlib.sha256(self.private_sign_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
        self.peer_public_sign_key = peer_public_sign_key
        self.peer_sign_key_hash = hashlib.sha256(self.peer_public_sign_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()

        self.local_ecc_keys: Dict[str, X25519PrivateKey] = {}
        self.remote_ecc_keys: Dict[str, X25519PublicKey] = {}

    def _add_local_ecc_key(self, private_key: X25519PrivateKey):
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()
        self.local_ecc_keys[public_key_hash] = private_key
        return public_key_hash

    def generate_local_ecc_key(self, size: int = 10):
        for _ in range(size):
            self._add_local_ecc_key(X25519PrivateKey.generate())

    def export_local_ecc_public_keys(self):  # expose public keys and sign
        export_keys = {}
        for key in self.local_ecc_keys:
            public_key_bytes = self.local_ecc_keys[key].public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            public_key_sign_bytes = self.private_sign_key.sign(public_key_bytes)
            export_keys[key] = (public_key_bytes, public_key_sign_bytes)
        return export_keys

    def add_local_ecc_key(self, private_key_bytes: bytes):
        private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        return self._add_local_ecc_key(private_key)

    def add_remote_ecc_key(self, public_key_bytes: bytes, public_key_sign_bytes: bytes):
        self.peer_public_sign_key.verify(public_key_sign_bytes, public_key_bytes)  # raise exception if invalid
        public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()
        self.remote_ecc_keys[public_key_hash] = X25519PublicKey.from_public_bytes(public_key_bytes)
        return public_key_hash

    def _derive_aes_key(self, local_ecc_key_hash: str, remote_ecc_key_hash: str, salt_bytes: Optional[bytes] = None):
        local_ecc_private_key = self.local_ecc_keys[local_ecc_key_hash]
        remote_ecc_public_key = self.remote_ecc_keys[remote_ecc_key_hash]

        shared_key = local_ecc_private_key.exchange(remote_ecc_public_key)
        hkdf_salt_bytes = salt_bytes or secrets.token_bytes(32)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=hkdf_salt_bytes,
            info=b"SecureChannelv1",
        ).derive(shared_key)

        return derived_key, hkdf_salt_bytes

    def _encrypt(self, local_ecc_key_hash: str, remote_ecc_key_hash: str, plaintext_bytes: bytes):
        aes_key_bytes, salt_bytes = self._derive_aes_key(local_ecc_key_hash, remote_ecc_key_hash)

        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(aes_key_bytes), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        # Add associated data
        encryptor.authenticate_additional_data(bytes.fromhex(self.sign_key_hash))
        ciphertext_bytes = encryptor.update(plaintext_bytes) + encryptor.finalize()

        timestamp = int(time.time())
        sign_buffer = bytes.fromhex(local_ecc_key_hash) + bytes.fromhex(remote_ecc_key_hash) + salt_bytes + ciphertext_bytes + nonce + encryptor.tag + timestamp.to_bytes(4, 'big')
        print(sign_buffer.hex())
        plaintext_sign_bytes = self.private_sign_key.sign(sign_buffer)

        return SecureMessage(
            sender_ecc_key_hash=local_ecc_key_hash,
            receiver_ecc_key_hash=remote_ecc_key_hash,
            salt=salt_bytes,
            ciphertext=ciphertext_bytes,
            nonce=nonce,
            tag=encryptor.tag,
            timestamp=timestamp,
            signature=plaintext_sign_bytes,
        )

    def encrypt(self, plaintext_bytes: bytes):
        # We are sender, local_ecc_key_hash should be in local cache
        local_ecc_key_hash = random.choice(list(self.local_ecc_keys.keys()))
        remote_ecc_key_hash = random.choice(list(self.remote_ecc_keys.keys()))
        return self._encrypt(local_ecc_key_hash, remote_ecc_key_hash, plaintext_bytes)

    def decrypt(self, message: SecureMessage):
        # verify the sign
        sign_buffer = bytes.fromhex(message.sender_ecc_key_hash) + bytes.fromhex(message.receiver_ecc_key_hash) + message.salt + message.ciphertext + message.nonce + message.tag + message.timestamp.to_bytes(4, 'big')
        self.peer_public_sign_key.verify(message.signature, sign_buffer)  # raise exception if invalid

        # We are receiver, message.receiver_ecc_key_hash should be in local cache
        aes_key_bytes, _ = self._derive_aes_key(message.receiver_ecc_key_hash, message.sender_ecc_key_hash, message.salt)
        cipher = Cipher(algorithms.AES(aes_key_bytes), modes.GCM(message.nonce, message.tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(bytes.fromhex(self.peer_sign_key_hash))

        plaintext_bytes = decryptor.update(message.ciphertext) + decryptor.finalize()

        return plaintext_bytes

    def sign(self, data: bytes) -> bytes:
        return self.private_sign_key.sign(data)

    def validate(self, data: bytes, signature: bytes):
        self.peer_public_sign_key.verify(signature, data)
