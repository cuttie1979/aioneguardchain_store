# AIOneGuardChain Storage functions: Backend
import asyncio
import base64
import boto3
import json
import os
import sys
import threading
import time
import traceback
from aioneguard.aioneguardchain.common.encrypted_message import Message
from aioneguard.aioneguardchain.common.helper.challenge import write_encrypted_file, read_challenge_file, add_challenge_response
from aioneguard.aioneguardchain.common.helper.configuration import save_config, load_config
from aioneguard.aioneguardchain.common.helper.utils import get_name_hash
from aioneguard.aioneguardchain.common.services.communication import CommunicationService
from aioneguard.utils import advanced_encrypt, logger_v2
from base64 import b64encode
from cryptography.hazmat.primitives import serialization
from getpass import getpass
from io import BytesIO


def _get_encrypt_password():
    if not os.path.exists('conf/.storecred'):
        return getpass(prompt='Enter your password: ')
    else:
        return open('conf/.storecred', 'r').read()


class Backend:

    def __init__(self):
        self._lock = threading.Lock()
        self._leader = None
        self._instance_id = None
        self._configuration = None
        self._communication_service = None
        self._file_registry = {}
        self._file_registry_file = None
        self._encryption_key = None

    @property
    def instance_id(self):
        return self._instance_id

    def run_init(self, backend_type: str, instance_id: str):
        if os.path.exists(f"conf/config_{instance_id}.bin"):
            logger_v2.log_warning("Configuration already exists...")
            sys.exit(1)
        if backend_type == 'fs':
            _path = None
            while _path is None or not os.path.exists(_path):
                _path = input("Enter a valid backend path: ")
            logger_v2.log_info(f"Initializing config: {backend_type} with path: {_path}...")
            self._instance_id = instance_id
            _encrypt_password = _get_encrypt_password()
            # Generate key
            _, _privpem, _, _pubpem, _pubhash, _kem, _pub_kem = advanced_encrypt.generate_keys()
            self._configuration = {
                "instance_id": instance_id,
                "data_folder": os.path.join(os.getcwd(), _path, instance_id),
                "cell_key": {
                    "private_key": b64encode(_privpem).decode(), "pub_key": b64encode(_pubpem).decode(),
                    "pubkey_hash": _pubhash, "kem": b64encode(advanced_encrypt.save_kem(_kem)).decode(),
                    "pub_kem": b64encode(_pub_kem).decode()
                }
            }
            if not os.path.exists(self._configuration['data_folder']):
                os.makedirs(self._configuration['data_folder'])
            save_config(self.instance_id, _encrypt_password, self._configuration)
        elif backend_type == 's3':
            s3_access_data = None
            _encrypt_password = _get_encrypt_password()
            while s3_access_data is None:
                _s3_server = None
                while _s3_server is None:
                    _s3_server = input("Enter an S3 server address: ")
                _s3_access_key = None
                while _s3_access_key is None:
                    _s3_access_key = input("Enter an S3 access key: ")
                _s3_secret_key = None
                while _s3_secret_key is None:
                    _s3_secret_key = input("Enter an S3 secret key: ")
                # Test the connection
                s3_client = boto3.client('s3', endpoint_url=f"https://{_s3_server}", aws_access_key_id=_s3_access_key,
                                         aws_secret_access_key=_s3_secret_key)
                s3_client.create_bucket(Bucket=self.instance_id)
                s3_client.upload_fileobj(Fileobj=BytesIO("TEST".encode()), Bucket=self.instance_id, Key="TEST")
                s3_client.delete_object(Bucket=self.instance_id, Key="TEST")
                logger_v2.log_info(f"S3 bucket {self.instance_id} test was successful.")
                s3_access_data = {"s3server": _s3_server, "access_key": _s3_access_key, "secret_key": _s3_secret_key}
            self._configuration['s3_access_data'] = s3_access_data
            save_config(self.instance_id, _encrypt_password, self._configuration)

    def run_challenge(self, instance_id: str):
        if os.path.exists(f"temp/challenge_{instance_id}.bin"):
            logger_v2.log_warning(
                f"Challenge file temp/challenge_{instance_id}.bin already exists, give the file to the storage admin...")
            sys.exit(1)
        self._instance_id = instance_id
        _encrypt_password = _get_encrypt_password()
        self._configuration = load_config(instance_id, _encrypt_password)
        _password = getpass(prompt='Enter the challenge encrypt password: ')
        _cell_key = self._configuration['cell_key']
        write_encrypted_file({
            "instance_id": self._instance_id, "pub_key": _cell_key['pub_key'], "pubkey_hash": _cell_key['pubkey_hash'],
            "pub_kem": _cell_key['pub_kem']
        }, _password, f"temp/challenge_{self.instance_id}.bin")
        logger_v2.log_info(f"Challenge successfully saved to: temp/challenge_{self.instance_id}.bin")

    def run_loadadminresponse(self, instance_id: str, file_path: str):
        _encrypt_password = _get_encrypt_password()
        self._configuration = load_config(instance_id, _encrypt_password)
        _, _response = read_challenge_file(file_path)
        add_challenge_response(self._configuration, _response, instance_id, _encrypt_password)

    async def run_start(self, instance_id: str):
        self._instance_id = instance_id
        if not os.path.exists('conf/.storecred'):
            _encrypt_password = getpass(prompt='Enter your password: ')
        else:
            _encrypt_password = open('conf/.storecred', 'r').read()
        self._configuration = load_config(instance_id, _encrypt_password)
        self._load_encrypt_key()
        self._file_registry_file = f"data/{instance_id}/{get_name_hash("file_registry")}"
        self._communication_service = CommunicationService(self.instance_id, self.process_message, None)
        self._communication_service.switch_keys(keys={
            "privkey": self._configuration['cell_key']['private_key'],
            "pubkey": self._configuration['cell_key']['pub_key'],
            "kem": self._configuration['cell_key']['kem'],
            "kem_pubkey": self._configuration['cell_key']['pub_kem'],
        }, pk_hash=self._configuration['cell_key']['pubkey_hash'])
        for _instance in self._configuration['master_nodes']:
            _data = self._configuration['master_nodes'][_instance]
            self._communication_service.add_address(_instance, _data['address'], _data['pubkey_hash'],
                                                    _data['pubkey_pem'], _data['pubkey_kem'])
        self._communication_service.subscribe_to_conn_change(self.connection_change)
        while True:
            await asyncio.sleep(1)

    def get_free_space(self):
        stat = os.statvfs(self._configuration["data_folder"])
        free_space = stat.f_bavail * stat.f_frsize
        return free_space

    def _get_s3_client(self):
        _s3_server = self._configuration['s3_access_data']["s3server"]
        _s3_access_key = self._configuration['s3_access_data']["access_key"]
        _s3_secret_key = self._configuration['s3_access_data']["secret_key"]
        return boto3.client('s3', endpoint_url=f"https://{_s3_server}", aws_access_key_id=_s3_access_key,
                            aws_secret_access_key=_s3_secret_key)

    async def process_message(self, _, payload: str, __, ___):
        try:
            _payload = json.loads(payload)
            logger_v2.log_debug(f"Message received: {json.dumps(_payload, indent=4)}")
            if _payload["type"] == "create_update_object_in_storage":
                _instance_id = _payload["instance_id"]
                _cluster = _payload["cluster"]
                _object_id = _payload["object_id"]
                _data = _payload["data"]
                if "data_folder" in self._configuration:
                    if not os.path.exists(f"{self._configuration["data_folder"]}/{get_name_hash(_cluster)}/"):
                        os.makedirs(f"{self._configuration["data_folder"]}/{get_name_hash(_cluster)}")
                    _file_name = f"{self._configuration["data_folder"]}/{get_name_hash(_cluster)}/{get_name_hash(_object_id)}"
                    self._store_encrypted_file(_file_name, _data)
                    _size = os.path.getsize(_file_name)
                else:
                    _file_name = f"{get_name_hash(_cluster)}/{get_name_hash(_object_id)}"
                    _size = len(_data)
                    _key = self._encryption_key
                    _encrypted_content = Message.create(_key["privkey"], _key["pubkey"], _key["kem"], _key["kem_pubkey"],
                                                        _key["pubkey_hash"], payload, self.instance_id)
                    self._get_s3_client().upload_fileobj(Fileobj=BytesIO(_encrypted_content.encode()), Bucket=self.instance_id, Key=_file_name)
                with self._lock:
                    if _cluster not in self._file_registry:
                        self._file_registry[_cluster] = {}
                    if _object_id not in self._file_registry[_cluster]:
                        self._file_registry[_cluster][_object_id] = {
                            "file_name": _file_name,
                            "create_date": time.time(),
                            "size": _size,
                        }
                    self._file_registry[_cluster][_object_id]["modify_date"] = time.time()
                self._persist_file_registry()
                if not os.path.exists(f"{self._configuration["data_folder"]}/{get_name_hash(_cluster)}"):
                    os.makedirs(f"{self._configuration["data_folder"]}/{get_name_hash(_cluster)}")
                _reply_message = {
                    "type": "create_update_object_in_storage_response",
                    "instance_id": self.instance_id,
                    "transaction_id": _payload["transaction_id"],
                    "free_space": self.get_free_space(),
                    "state": "SUCCESS"
                }
                logger_v2.log_debug(f"Sending reply message to instance: {_instance_id}")
                self._communication_service.send_instance_message(_instance_id, json.dumps(_reply_message))
            elif _payload["type"] == "read_storage_object":
                _cluster = _payload["cluster"]
                _object_id = _payload["object_hash"]
                if "data_folder" in self._configuration:
                    _data = self._get_encrypted_file(f"{self._configuration["data_folder"]}/{get_name_hash(_cluster)}/{get_name_hash(_object_id)}")
                else:
                    _data = self._get_s3_client().get_object(Bucket=self.instance_id, Key=f"{get_name_hash(_cluster)}/{get_name_hash(_object_id)}")
                _recipient = _payload["instance_id"]
                _reply_message = {
                    "type": "read_object_store_response",
                    "client": _payload["client"],
                    "object_hash": _payload["object_hash"],
                    "data": _data
                }
                self._communication_service.send_instance_message(_recipient, json.dumps(_reply_message))
            elif _payload["type"] == "delete_storage_object":
                _cluster = _payload["cluster"]
                _object_id = _payload["object_hash"]
                if "data_folder" in self._configuration:
                    self._delete_encrypted_file(f"{self._configuration["data_folder"]}/{get_name_hash(_cluster)}/{get_name_hash(_object_id)}")
                else:
                    self._get_s3_client().delete_object(Bucket=self.instance_id, Key=f"{get_name_hash(_cluster)}/{get_name_hash(_object_id)}")
            else:
                logger_v2.log_warning(f"Error unknown message type: {_payload["type"]}")
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while processing message: {e}")

    def connection_change(self, instance_id: str, connection_new_state: str):
        if connection_new_state == "CONNECTED":
            if self._leader is None:
                self._communication_service.send_instance_message(instance_id, json.dumps({"type": "storagecell_hello", "instance_id": self._instance_id}))

    def _load_encrypt_key(self):
        _key = self._configuration['cell_key']
        self._encryption_key = {
            "privkey": serialization.load_pem_private_key(base64.b64decode(_key["private_key"]), password=None),
            "pubkey": serialization.load_pem_public_key(base64.b64decode(_key["pub_key"])),
            "pubkey_hash": _key["pubkey_hash"],
            "kem": advanced_encrypt.restore_kem(base64.b64decode(_key["kem"])),
            "kem_pubkey": base64.b64decode(_key["pub_kem"])
        }

    def _store_encrypted_file(self, file_path: str, payload: str):
        try:
            _key = self._encryption_key
            _encrypted_content = Message.create(_key["privkey"], _key["pubkey"], _key["kem"], _key["kem_pubkey"], _key["pubkey_hash"], payload,
                                                self.instance_id)
            with open(file_path, "w") as f:
                f.write(_encrypted_content)
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while storing encrypted file: {e}")

    def _get_encrypted_file(self, file_path: str):
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File: {file_path} not found")
            _key = self._encryption_key
            return Message.decode_message(_key["privkey"], _key["pubkey"], _key["kem"], open(file_path, "r").read())
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while getting the encrypted file: {e}")

    @staticmethod
    def _delete_encrypted_file(file_path: str):
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File: {file_path} not found")
            else:
                os.remove(file_path)
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while deleting encrypted file: {e}")

    def _persist_file_registry(self):
        try:
            with self._lock:
                self._store_encrypted_file(self._file_registry_file, json.dumps(self._file_registry))
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while storing file registry: {e}")

    def _restore_file_registry(self):
        try:
            if os.path.exists(self._file_registry_file):
                with self._lock:
                    self._file_registry = self._get_encrypted_file(self._file_registry_file)
            else:
                self._persist_file_registry()
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while restoring file registry: {e}")
