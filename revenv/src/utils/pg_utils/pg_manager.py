from typing import Dict
from src.utils.pg_utils.payload_generator import PayloadGenerator


class PGManager:
    def __init__(self):
        self.payload_sessions: Dict[str, PayloadGenerator] = {}

    def create_instance(self, user: str, file_path: str) -> PayloadGenerator:
        payload_generator = PayloadGenerator(file_path)
        self.payload_sessions[user] = payload_generator
        return payload_generator

    def get_instance_by_user(self, user: str) -> PayloadGenerator:
        return self.payload_sessions.get(user)
