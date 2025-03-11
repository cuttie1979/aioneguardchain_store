# AIOneGuardChain - Common: Communication Service
import asyncio
import json
import os
import threading
import traceback
import uuid
from base64 import b64encode, b64decode
import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from aioneguard.aioneguardchain.common import constants
from aioneguard.aioneguardchain.common.encrypted_message import Message
from aioneguard.utils import advanced_encrypt, logger_v2


class CommunicationService:

    def __init__(self, instance_id: str, process_message: callable, get_leader: callable):
        self._lock = threading.Lock()
        self._instance_id = instance_id
        self._process_message = process_message
        self.communication_enabled = True
        self._node_communication = {}  # Nodes for master cluster communication
        self._conn_change_subscribers = []
        self._web_private_key = None
        self._web_private_kem = None
        self._web_public_key_pem = None
        self._web_public_key_hash = None
        self._web_public_kem = None
        self._generate_webconnect_keys()
        self._get_leader = get_leader

    @property
    def web_public_key_pem(self):
        return self._web_public_key_pem

    @property
    def web_public_kem(self):
        return self._web_public_kem

    @property
    def web_public_key_hash(self):
        return self._web_public_key_hash

    @property
    def node_communication(self):
        return self._node_communication

    def _generate_webconnect_keys(self):
        (self._web_private_key, _, _, _wpkpem,
         self._web_public_key_hash, self._web_private_kem, _public_kem) = advanced_encrypt.generate_keys()
        self._web_public_key_pem = b64encode(_wpkpem).decode()
        self._web_public_kem = b64encode(_public_kem).decode()
        logger_v2.log_info(log_msg="WEBConnect keys generated")

    def switch_keys(self, keys: dict, pk_hash: str):
        self._web_private_key = serialization.load_pem_private_key(b64decode(keys["privkey"]), password=None)
        self._web_public_key_hash = pk_hash
        self._web_public_key_pem = keys["pubkey"]
        self._web_private_kem = advanced_encrypt.restore_kem(b64decode(keys["kem"]))
        self._web_public_kem = keys["kem_pubkey"]
        logger_v2.log_info("WEBConnect keys switched to the node keys...")

    def decode_message(self, msg: str, keydata: dict):
        try:
            return Message.decode_message(self._web_private_key, keydata["public_key"], self._web_private_kem, msg)
        except Exception as e:
            logger_v2.log_error(f"Error while decoding message: {e}")
        return None

    def create_anonym_message(self, peer_public_key: EllipticCurvePublicKey, peer_publickey_kem: bytes, payload: str):
        try:
            return Message.create(
                self._web_private_key, peer_public_key, self._web_private_kem, peer_publickey_kem, self.web_public_key_hash, payload, self._instance_id
            )
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while creating message: {e}")

    def broadcast_message(self, message: str):
        for _instance in self.get_connected_nodes():
            self.send_instance_message(_instance, message)
        logger_v2.log_debug("Message broadcasted...")

    def send_instance_message(self, instance_id: str, payload: str):
        if instance_id in self._node_communication:
            if self._node_communication[instance_id]["state"] == constants.ConnectionState.CONNECTED:
                _msg = self.create_anonym_message(self._node_communication[instance_id]["pubkey"], self._node_communication[instance_id]["pubkem"],
                                                  payload=payload)
                asyncio.create_task(self._send_ws_message(self._node_communication[instance_id]["ws"], _msg))

    @staticmethod
    async def _send_ws_message(ws, msg):
        try:
            await ws.send(msg)
        except Exception as e:
            traceback.print_exc()
            logger_v2.log_error(f"Error while sending websocket message: {e}")

    def get_stats(self):
        _data = {"node_communication_connected_masternodes": ", ".join(self.get_connected_nodes())}
        for _instance in self._node_communication.keys():
            _data[f"node_communication__masternodestate_{_instance}"] = self._node_communication[_instance]["state"]
        return ["\n### COMMUNICATION SERVICE"] + [f"{key} {_data[key]}" for key in _data]

    def add_address(self, instance_id: str, address: str, pubkey_hash: str, pubkey_pem: str, pubkey_kem: str):
        if instance_id not in self._node_communication:
            with self._lock:
                self._node_communication[instance_id] = {
                    "ws": None, "address": address, "state": constants.ConnectionState.DISCONNECTED, "pubkey_hash": pubkey_hash,
                    "pubkey": serialization.load_pem_public_key(b64decode(pubkey_pem)), "pubkem": b64decode(pubkey_kem),
                }
                logger_v2.log_info(log_msg=f"Websocket server connection to {address} added...")
            asyncio.create_task(self.start_websocket_connection(instance_id=instance_id))
        else:
            logger_v2.log_info(f"Already connected to {address}")

    async def start_websocket_connection(self, instance_id: str):
        _address = self._node_communication[instance_id]["address"]
        while self.communication_enabled:
            try:
                _session_id = f"{instance_id}_client-{uuid.uuid4().hex}"
                async with websockets.connect(f"{os.getenv("WS_SCHEME", "ws")}://{_address}/encrypted") as websocket:
                    self._node_communication[instance_id]["ws"] = websocket
                    await asyncio.sleep(1)      # Ensure the websocket connection fully up
                    self._update_connection(instance_id, constants.ConnectionState.CONNECTED)
                    if os.getenv("NODE_TYPE") == "MASTER":
                        self.send_instance_message(instance_id, json.dumps({"type": "node_hello", "instance": self._instance_id, "leader": self._get_leader()}))
                    logger_v2.log_info(log_msg=f"Websocket connection to {_address} ready...")
                    while self.communication_enabled:
                        try:
                            data = await websocket.recv()
                            _sender = b64decode(data)[0:128].decode()
                            _payload = self.decode_message(msg=data, keydata={"public_key": self._node_communication[instance_id]["pubkey"]})
                            if _payload is not None:
                                asyncio.create_task(self._process_message(websocket, _payload, _session_id, _sender))
                        except websockets.exceptions.ConnectionClosedError:
                            self._update_connection(instance_id, constants.ConnectionState.DISCONNECTED)
                            break
            except (websockets.exceptions.WebSocketException, ConnectionRefusedError):
                self._update_connection(instance_id, constants.ConnectionState.DISCONNECTED)
                await asyncio.sleep(5)

    def get_connected_nodes(self):
        with self._lock:
            return [
                instance_id for instance_id in self._node_communication.keys()
                if self._node_communication[instance_id]["state"] == constants.ConnectionState.CONNECTED
            ]

    def subscribe_to_conn_change(self, method: callable):
        if method not in self._conn_change_subscribers:
            self._conn_change_subscribers.append(method)

    def unsubscribe_from_conn_change(self, method: callable):
        if method in self._conn_change_subscribers:
            self._conn_change_subscribers.remove(method)

    def _run_connection_change_methods(self, instance_id: str, connection_new_state: str):
        for _method in self._conn_change_subscribers:
            _method(instance_id=instance_id, connection_new_state=connection_new_state)

    def _update_connection(self, instance_id: str, connection_new_state: str):
        if connection_new_state != self._node_communication[instance_id]["state"]:
            logger_v2.log_debug(f"Connection to instance: {instance_id[0:10]}...{instance_id[-3:]} changed to {connection_new_state}")
        with self._lock:
            self._node_communication[instance_id]["state"] = connection_new_state
        self._run_connection_change_methods(instance_id, connection_new_state)
