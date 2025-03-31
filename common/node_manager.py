import hashlib
import urllib.parse
from typing import Any, Optional
import uuid
import requests
import secrets
import getpass
import json
import os
import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config_db import ConfigStore


def load_key_from_store(store: ConfigStore) -> Ed25519PrivateKey:
    private_sign_key_pem = store.get_node_config('privateKey')
    assert private_sign_key_pem is not None, 'privateKey not found'
    assert isinstance(private_sign_key_pem, str), 'privateKey must be a string'

    private_sign_key = serialization.load_pem_private_key(private_sign_key_pem.encode(), None)
    assert isinstance(private_sign_key, Ed25519PrivateKey), 'privateKey is not a valid Ed25519 private key'
    
    return private_sign_key


class NodeManager:
    def __init__(self, db: ConfigStore) -> None:
        self.db = db
        
        self.private_sign_key = load_key_from_store(self.db)
        self.public_sign_key = self.private_sign_key.public_key()
        
        public_bytes = self.public_sign_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_sign_key_hash = hashlib.sha256(public_bytes).hexdigest()

        node_id = self.db.get_node_config('nodeId')
        assert node_id is not None, 'nodeId not found'
        assert isinstance(node_id, int), 'nodeId must be an integer'
        self.node_id = node_id
        
        self.domain_prefix = self.db.get_node_config('domainPrefix')
        assert self.domain_prefix is not None, 'domainPrefix not found'
        assert isinstance(self.domain_prefix, str), 'domainPrefix must be a string'
    
    def do_get(self, url: str, params: Optional[dict[str, Any]] = None):
        nonce = secrets.token_hex(16)
        sign_params = params.copy() if params else {}
        querystring = urllib.parse.urlencode(sorted(sign_params.items()))
        to_sign = "{}\n{}\n{}".format(url, nonce, querystring)
        signature = self.private_sign_key.sign(to_sign.encode()).hex()
        
        headers = {
            'X-Client-Id': self.public_sign_key_hash,
            'X-Client-Nonce': nonce,
            'X-Client-Sign': signature,
        }
        r = requests.get("{}{}?{}".format(self.domain_prefix, url, querystring), headers=headers)
        if r.status_code != 200:
            raise Exception('GET {} failed with status {}: {}'.format(url, r.status_code, r.text))

        return r.json()

    def do_post(self, url: str, data: Optional[dict[str, Any]] = None):
        nonce = secrets.token_hex(16)
        sign_params = data.copy() if data else {}
        to_sign = "{}\n{}\n{}".format(url, nonce, json.dumps(sign_params, ensure_ascii=False))
        signature = self.private_sign_key.sign(to_sign.encode()).hex()
        
        headers = {
            'X-Client-Id': self.public_sign_key_hash,
            'X-Client-Nonce': nonce,
            'X-Client-Sign': signature,
        }
        r = requests.post("{}{}".format(self.domain_prefix, url), headers=headers, json=data)
        if r.status_code != 200:
            raise Exception('POST {} failed with status {}: {}'.format(url, r.status_code, r.text))

        return r.json()

    def init_keystore(self, expect_number: int = 10):
        local_keys = self.db.get_all_wg_keys()
        if len(local_keys) >= expect_number:
            print("{} keys found in local keystore".format(len(local_keys)))
            return
        
        print("No keys found in local keystore, generating new keys...")
        for _ in range(expect_number - len(local_keys)):
            new_wg_private = subprocess.check_output(["wg", "genkey"], encoding='utf-8').strip()
            new_wg_pubic = subprocess.check_output(["wg", "pubkey"], encoding='utf-8', input=new_wg_private).strip()
            self.db.create_wg_key(new_wg_private, new_wg_pubic)
            print("Generated new key: {}".format(new_wg_pubic))

    def sync_keystore(self):
        local_keys = self.db.get_all_wg_keys()
        if not local_keys:
            print("No keys found in local keystore")
            return
        
        wg_public_keys = [keypair[1] for keypair in local_keys]
        return self.do_post("/api/v1/node/sync_wireguard_keys", {
            "keys": wg_public_keys,
        })

    def get_info(self):
        return self.do_get("/api/v1/node/info")

    def get_peers(self):
        return self.do_get("/api/v1/node/peers")

    def get_config(self):
        return self.do_get("/api/v1/node/config")


def init_node(store_path: str):
    if os.path.exists(store_path):
        raise Exception('store already initialized: {}'.format(store_path))

    config_store = ConfigStore(store_path)
    
    print('Generating private key...')
    private_key = Ed25519PrivateKey.generate()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    config_store.set_node_config('privateKey', private_key_pem.decode())
    
    return config_store


def join_cluster(store: ConfigStore, domainPrefix: str, token: str, name: str = ''):
    current_domain_prefix = store.get_node_config('domainPrefix')
    if current_domain_prefix:
        raise Exception('Already joined cluster: {}'.format(current_domain_prefix))

    private_key = load_key_from_store(store)
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    use_domain_prefix = domainPrefix
    if not use_domain_prefix.startswith('http://') and not use_domain_prefix.startswith('https://'):
        use_domain_prefix = 'https://' + use_domain_prefix
    
    if not use_domain_prefix.startswith("https://"):
        print("[WARNING] domainPrefix is in HTTP protocol and is not secure!")

    r = requests.post("{}/api/v1/node/join".format(use_domain_prefix), json={
        "token": token,
        "name": name or str(uuid.uuid4()),
        "publicSignKey": public_key_pem.decode(),
    })
    if r.status_code != 200:
        raise Exception('Failed to join cluster: {}'.format(r.text))
    
    data = r.content
    print(data)
    data = json.loads(data)
    node_id = int(data['id'])
    
    # save node id
    store.set_node_config('nodeId', node_id)
    store.set_node_config('domainPrefix', use_domain_prefix)


def get_or_init_node_interactive(store_path: str):
    if os.path.exists(store_path):
        store = ConfigStore(store_path)
    else:
        store = init_node(store_path)
        eth_name = input("Ethernet Interface Name: ")
        assert eth_name, "Ethernet Interface Name cannot be empty"
        store.set_node_config('ethName', eth_name)

        namespace = input("Network Namespace: ")
        if not namespace:
            namespace = "lspnet"
        store.set_node_config('namespace', namespace)

    domain_prefix = store.get_node_config('domainPrefix')
    if not domain_prefix:
        print("node initialized, but not joined to cluster")
        domain_prefix = input("Domain Prefix: ")
        token = getpass.getpass("Token: ")

        join_cluster(store, domain_prefix, token)
    
    return NodeManager(store)
