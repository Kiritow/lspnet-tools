import base64
import time
import secrets
import requests
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .secure_channel import SecureMessage, SecureChannelClient


class NodeManager:
    def __init__(self, node_name: str, domain_prefix: str, node_private_sign_key_pem: bytes, controller_public_sign_key_pem: bytes) -> None:
        node_private_sign_key = serialization.load_pem_private_key(node_private_sign_key_pem, None)
        controller_public_sign_key = serialization.load_pem_public_key(controller_public_sign_key_pem)
        if not isinstance(node_private_sign_key, Ed25519PrivateKey) or not isinstance(controller_public_sign_key, Ed25519PublicKey):
            raise ValueError('Invalid key type')
        self.domain_prefix = domain_prefix
        if not self.domain_prefix.startswith('https://') and not self.domain_prefix.startswith('http://'):
            self.domain_prefix = 'https://' + self.domain_prefix
        self.node_name = node_name
        
        self.client = SecureChannelClient(node_private_sign_key, controller_public_sign_key)
        self.valid_until: float = 0

    def connect(self):
        public_key_der_bytes, public_key_sign_bytes = self.client.get_handshake()
        data = {
            "name": self.node_name,
            "key": base64.b64encode(public_key_der_bytes).decode(),
            "sign": base64.b64encode(public_key_sign_bytes).decode(),
        }
        r = requests.post(f'{self.domain_prefix}/node/connect', json=data)
        if r.status_code != 200:
            raise Exception(f'POST /node/connect failed with status {r.status_code}, error: {r.content}')

        res = json.loads(r.content)
        self.client.complete_handshake(base64.b64decode(res["key"]), base64.b64decode(res["sign"]), res["cid"])
        handshake_data_bytes = self.client.decrypt(SecureMessage.from_bytes(base64.b64decode(res["data"])))
        handshake_data = json.loads(handshake_data_bytes)
        self.valid_until = (handshake_data["exp"] / 1000) - 300  # 5 minutes grace period

    def ensure_connection(self):
        '''
        :returns: True if connection is newly created
        '''
        
        if self.client.ready() and time.time() < self.valid_until:
            return False

        self.client.reset()
        self.connect()
        return True

    def _post_json(self, url: str, data: dict, retry_connection: bool = True) -> dict:
        self.ensure_connection()
        send_msg = self.client.encrypt(json.dumps(data).encode())
        print(send_msg);
        r = requests.post(f'{self.domain_prefix}{url}', data=send_msg.to_bytes())
        if r.status_code == 410:  # Gone
            self.valid_until = 0
            if retry_connection:
                return self._post_json(url, data, False)
            raise Exception('Connection expired')
        if r.status_code != 200:
            raise Exception(f'POST {url} failed with status {r.status_code}, error: {r.content}')

        recv_msg = SecureMessage.from_bytes(r.content)
        resp = self.client.decrypt(recv_msg)
        return json.loads(resp)

    def hello(self):
        return self._post_json('/node/hello', {
            "name": self.node_name,
            "message": secrets.token_bytes(16).hex(),
        })
