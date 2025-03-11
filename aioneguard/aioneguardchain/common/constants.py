# AIOneGuardChain - Common: Constants
from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectionState:
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"


@dataclass(frozen=True)
class TransactionState:
    CREATED = "CREATED"
    STORED = "STORED"
    COMMITTED = "COMMITTED"
    CLIENT_COMMIT_SENT = "CLIENT_COMMIT_SENT"
    COMMITMENT_RECORDED = "COMMITMENT_RECORDED"
    FINISHED = "FINISHED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class MessageState:
    CREATED = "CREATED"
    SENT = "SENT"
    PROCESSED = "PROCESSED"
