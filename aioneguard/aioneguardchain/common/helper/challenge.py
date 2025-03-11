# AIOneGuardChain - Challenge file helper
import json
import traceback
from getpass import getpass

from aioneguard.utils import advanced_encrypt, logger_v2

from aioneguard.aioneguardchain.common.helper.configuration import save_config


def read_challenge_file(file_path):
    _file_password = None
    _challenge = None
    _file_data = open(file_path, 'rb').read()
    while _challenge is None:
        try:
            _salt = _file_data[0:16]
            _encrypted_payload = _file_data[16:]
            _file_password = getpass("Enter the challenge file password: ")
            _key = advanced_encrypt.derive_key_from_password(_file_password, _salt)
            _payload = advanced_encrypt.aes_decrypt(_key, _encrypted_payload).decode()
            _challenge = json.loads(_payload)
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while decrypting the challenge file: {e}")
    logger_v2.log_info("Challenge loaded...")
    return _file_password, _challenge


def write_encrypted_file(file_data: dict, file_password: str, output_file: str):
    _salt = advanced_encrypt.generate_salt()
    _payload = advanced_encrypt.aes_encrypt(advanced_encrypt.derive_key_from_password(file_password, _salt),
                                            json.dumps(file_data).encode())
    with open(output_file, "wb") as f:
        f.write(_salt + _payload)


def add_challenge_response(configuration: dict, challenge_response: dict, instance_id: str, encrypt_password: str):
    if "master_nodes" not in configuration:
        configuration['master_nodes'] = challenge_response['master_nodes']
        save_config(instance_id, encrypt_password, configuration)
        logger_v2.log_info("Configuration successfully updated...")
    else:
        logger_v2.log_info("Masternodes already loaded...")
        _overwrite = None
        while _overwrite is None or _overwrite not in ["y", "n"]:
            _overwrite = input("Do you want to overwrite the master nodes? [y/n]: ").lower()
        if _overwrite == "y":
            configuration['master_nodes'] = challenge_response['master_nodes']
            save_config(instance_id, encrypt_password, configuration)
            logger_v2.log_info("Configuration successfully updated...")
