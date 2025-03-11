# Program: AIOneGuardChain Common: Datatypes
from pydantic import BaseModel


class HelloRequest(BaseModel):
    instance_id: str
    pubkey: str
    kem_pubkey: str
    hash: str
    address: str
