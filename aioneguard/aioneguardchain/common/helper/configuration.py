# Configuration tools
import json
import sys
import traceback
from base64 import b64encode
from aioneguard.utils import advanced_encrypt, logger_v2


def save_config(instance_id: str, encrypt_password: str, configuration: dict):
    try:
        _salt = advanced_encrypt.generate_salt()
        _key = advanced_encrypt.derive_key_from_password(encrypt_password, _salt)
        _data = json.dumps(configuration).encode()
        _associated_data = b64encode(instance_id.encode())
        _associated_data_len = len(_associated_data).to_bytes(4, 'big')
        _encrypted_payload = advanced_encrypt.aes_encrypt(_key, _data, _associated_data)
        with open(f"conf/config_{instance_id}.bin", "wb") as f:
            f.write(_associated_data_len + _associated_data + _salt + _encrypted_payload)
        logger_v2.log_info("Encrypted configuration saved...")
    except Exception as e:
        traceback.print_exc()
        logger_v2.log_error(f"Error while saving the admin configuration: {e}")


def load_config(instance_id: str, encrypt_password: str) -> dict:
    try:
        _payload = open(f"conf/config_{instance_id}.bin", "rb").read()
        _associated_data_len = int.from_bytes(_payload[0:4], 'big')
        _key = advanced_encrypt.derive_key_from_password(
            encrypt_password, _payload[_associated_data_len + 4:_associated_data_len + 20])
        _decrypted_payload = advanced_encrypt.aes_decrypt(
            _key, _payload[20 + _associated_data_len:], _payload[4:_associated_data_len + 4])
        logger_v2.log_info("Encrypted configuration successfully decrypted...")
        return json.loads(_decrypted_payload.decode())
    except Exception as Ex:
        traceback.print_exc()
        logger_v2.log_error(f"Error while loading the admin configuration: {Ex}")
        sys.exit(1)
