#############################################
# Author: Laszlo Popovics                   #
# Version: 1.0                              #
# Program: AIOneGuardStore - Message Object #
#############################################

# import the required libraries
import base64
import traceback
from aioneguard.utils import advanced_encrypt, logger_v2
from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from oqs import KeyEncapsulation

backend = default_backend()
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)


class Message:

    @staticmethod
    def create(private_key: EllipticCurvePrivateKey, peer_public_key: EllipticCurvePublicKey,
               kem_private: KeyEncapsulation, peer_kem_public: bytes, own_hash: str, payload: str, instance_id: str):
        try:
            _salt = advanced_encrypt.generate_salt()
            _key, _kem_cipher = advanced_encrypt.derive_shared_key(
                private_key, peer_public_key, kem_private, peer_kem_public, own_hash, _salt)
            _data = base64.b64encode(instance_id.encode())
            _a_data_len = len(_data).to_bytes(4, 'big')
            _kem_cipher_len = len(_kem_cipher).to_bytes(4, 'big')
            _enc_payload = advanced_encrypt.aes_encrypt(_key, payload.encode(), _data)
            return base64.b64encode(
                own_hash.encode() + _salt + _a_data_len + _data + _kem_cipher_len + _kem_cipher + _enc_payload
            ).decode()
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_warning(f"Message creation failed: {e}")
        return None

    @staticmethod
    def decode_message(private_key: EllipticCurvePrivateKey, peer_public_key: EllipticCurvePublicKey,
                       kem_private: KeyEncapsulation, encrypted_message: str):
        try:
            _payload = base64.b64decode(encrypted_message)
            _peer_hash = _payload[0:128].decode()
            _salt = _payload[128:144]
            _associated_data_len = int.from_bytes(_payload[144:148], 'big')
            _associated_data = _payload[148:148 + _associated_data_len]
            _kem_cipher_len = int.from_bytes(_payload[148 + _associated_data_len:152+_associated_data_len], 'big')
            _kem_cipher = _payload[152+_associated_data_len:152+_associated_data_len+_kem_cipher_len]
            _encrypted_bytes = _payload[152+_associated_data_len+_kem_cipher_len:]
            _ecdh_secret = private_key.exchange(ec.ECDH(), peer_public_key)
            _kem_secret = advanced_encrypt.decap_kem(kem_private, _kem_cipher)
            _combined_secret = _ecdh_secret + _kem_secret
            _hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=_salt,
                info=b"HybridKeyDerivation_v1_" + _peer_hash.encode('utf-8'),
                backend=backend
            )
            _pre_key = _hkdf.derive(_combined_secret)
            _key = ph.hash(_pre_key, salt=_salt)[29:].encode('utf-8')[:32]
            return advanced_encrypt.aes_decrypt(_key, _encrypted_bytes, _associated_data).decode()
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_warning(f"Message decoding failed: {e}")
        return None


if __name__ == "__main__":
    alice_priv, alice_priv_pem, alice_pub, alice_pub_pem, alice_hash, alice_kem, alice_kem_pub = advanced_encrypt.generate_keys()
    bob_priv, bob_priv_pem, bob_pub, bob_pub_pem, bob_hash, bob_kem, bob_kem_pub = advanced_encrypt.generate_keys()
    _msg = Message.create(alice_priv, bob_pub, alice_kem, bob_kem_pub, alice_hash, "Test", "test_instance")
    # Message created
    _decoded_msg = Message.decode_message(
        bob_priv, alice_pub, bob_kem, _msg
    )
    print(_decoded_msg)

