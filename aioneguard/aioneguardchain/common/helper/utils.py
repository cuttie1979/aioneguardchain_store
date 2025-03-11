# AIOneGuardChain - Utility functions
from hashlib import sha3_256, blake2s


def get_name_hash(name: str):
    return sha3_256(name.encode()).hexdigest() + blake2s(name.encode()).hexdigest()