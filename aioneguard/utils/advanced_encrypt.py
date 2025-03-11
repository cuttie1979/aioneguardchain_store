# Advanced Encryption module
from argon2.exceptions import HashingError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import hashlib
import secrets
import oqs
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
backend = default_backend()


def generate_keys():
    private_key = ec.generate_private_key(ec.SECP521R1(), backend)
    public_key = private_key.public_key()
    privkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pubkey_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pubkey_hash = get_hash(pubkey_pem)
    kem = oqs.KeyEncapsulation("Kyber1024")
    kem_public_key = kem.generate_keypair()
    return private_key, privkey_pem, public_key, pubkey_pem, pubkey_hash, kem, kem_public_key


def generate_salt():
    return secrets.token_bytes(16)


def get_hash(data_for_hash):
    hash_object = hashlib.sha3_512()
    hash_object.update(data_for_hash)
    return hash_object.hexdigest()


def derive_shared_key(private_key, peer_public_key, kem_private, peer_kem_public, own_hash, salt, key_length=32):
    if private_key.curve.name != "secp521r1" or peer_public_key.curve.name != "secp521r1":
        raise ValueError("Both keys must use SECP521R1")
    if not own_hash or not salt:
        raise ValueError("own_hash and salt must be non-empty")
    ecdh_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    if not ecdh_secret or ecdh_secret == b'\x00' * len(ecdh_secret):
        raise RuntimeError("Invalid ECDH secret")
    kem_ciphertext, kem_secret = kem_private.encap_secret(peer_kem_public)
    combined_secret = ecdh_secret + kem_secret
    hkdf_instance = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=salt,
        info=b"HybridKeyDerivation_v1_" + own_hash.encode('utf-8'),
        backend=backend
    )
    pre_key = hkdf_instance.derive(combined_secret)
    final_key = ph.hash(pre_key, salt=salt)[29:].encode('utf-8')
    return final_key[:key_length], kem_ciphertext


def decap_kem(kem_private, kem_ciphertext):
    return kem_private.decap_secret(kem_ciphertext)



def derive_key_from_password(password: str, salt: bytes, time_cost: int = 3, memory_cost: int = 65536,
                             parallelism: int = 4, key_length: int = 32) -> bytes:
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes")
    if time_cost < 1 or memory_cost < 1024 or parallelism < 1 or key_length < 16:
        raise ValueError("Invalid parameter values")

    try:
        _ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            salt_len=len(salt)
        )
        # Use provided salt instead of letting Argon2 generate one
        hashed = _ph.hash(password, salt=salt)
        # Strip Argon2 preamble (e.g., "$argon2id$v=19$...$") and return raw bytes
        return hashed.split("$")[-1].encode('utf-8')[:key_length]
    except HashingError as e:
        raise HashingError(f"Failed to derive key: {str(e)}")


def aes_encrypt(key, data, associated_data=b""):
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key[:32])
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)
    h = hmac.HMAC(key[32:], hashes.SHA3_512(), backend=backend)
    h.update(nonce + ciphertext + associated_data)
    hmac_tag = h.finalize()
    return nonce + ciphertext + hmac_tag


def aes_decrypt(key, encrypted_bytes, associated_data=b""):
    nonce = encrypted_bytes[:12]
    hmac_tag = encrypted_bytes[-64:]
    ciphertext = encrypted_bytes[12:-64]
    h = hmac.HMAC(key[32:], hashes.SHA3_512(), backend=backend)
    h.update(nonce + ciphertext + associated_data)
    h.verify(hmac_tag)
    aesgcm = AESGCM(key[:32])
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def sign_data(data, private_key):
    return private_key.sign(data=data, signature_algorithm=ec.ECDSA(hashes.SHA3_512()))


def verify_signature(data, data_signature, public_key):
    try:
        public_key.verify(signature=data_signature, data=data, signature_algorithm=ec.ECDSA(hashes.SHA3_512()))
        return True
    except InvalidSignature:
        return False


def save_kem(kem: oqs.KeyEncapsulation) -> bytes:
    return kem.export_secret_key()


def restore_kem(kem_bytes: bytes) -> oqs.KeyEncapsulation:
    return oqs.KeyEncapsulation(alg_name="Kyber1024", secret_key=kem_bytes)


if __name__ == "__main__":
    alice_priv, alice_priv_pem, alice_pub, alice_pub_pem, alice_hash, alice_kem, alice_kem_pub = generate_keys()
    bob_priv, bob_priv_pem, bob_pub, bob_pub_pem, bob_hash, bob_kem, bob_kem_pub = generate_keys()
    msg_salt = generate_salt()
    alice_key, alice_kem_cipher = derive_shared_key(alice_priv, bob_pub, alice_kem, bob_kem_pub, alice_hash, msg_salt)
    message = b"Top secret message!"
    encrypted_data = aes_encrypt(alice_key, message, b"metadata")
    bob_ecdh_secret = bob_priv.exchange(ec.ECDH(), alice_pub)
    bob_kem_secret = decap_kem(bob_kem, alice_kem_cipher)
    bob_combined_secret = bob_ecdh_secret + bob_kem_secret
    bob_hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=msg_salt,
        info=b"HybridKeyDerivation_v1_" + alice_hash.encode('utf-8'),
        backend=backend
    )
    bob_pre_key = bob_hkdf.derive(bob_combined_secret)
    bob_key = ph.hash(bob_pre_key, salt=msg_salt)[29:].encode('utf-8')[:32]
    decrypted = aes_decrypt(bob_key, encrypted_data, b"metadata")
    print(f"Original: {message.decode('utf-8')}")
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    signature = sign_data(message, alice_priv)
    is_valid = verify_signature(message, signature, alice_pub)
    print(f"Signature valid: {is_valid}")
