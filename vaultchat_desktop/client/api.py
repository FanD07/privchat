from __future__ import annotations

from typing import Any, Dict, List

import httpx


class ApiClient:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')
        self.http = httpx.Client(base_url=self.server_url, timeout=15.0)

    def create_group(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        response = self.http.post('/bootstrap/create-group', json=payload)
        response.raise_for_status()
        return response.json()

    def join_group(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        response = self.http.post('/group/join', json=payload)
        response.raise_for_status()
        return response.json()

    def get_members(self, token: str) -> List[Dict[str, Any]]:
        response = self.http.get('/group/members', headers={'Authorization': f'Bearer {token}'})
        response.raise_for_status()
        return response.json()['members']

    def get_group_messages(self, token: str) -> List[Dict[str, Any]]:
        response = self.http.get('/messages/group', headers={'Authorization': f'Bearer {token}'})
        response.raise_for_status()
        return response.json()['messages']

    def get_dm_messages(self, token: str, other_user_id: str) -> List[Dict[str, Any]]:
        response = self.http.get(f'/messages/dm/{other_user_id}', headers={'Authorization': f'Bearer {token}'})
        response.raise_for_status()
        return response.json()['messages']

    def send_group_message(self, token: str, envelope: Dict[str, Any]) -> None:
        response = self.http.post('/messages/group', json={'envelope': envelope}, headers={'Authorization': f'Bearer {token}'})
        response.raise_for_status()

    def send_dm_message(self, token: str, payload: Dict[str, Any]) -> None:
        response = self.http.post('/messages/dm', json=payload, headers={'Authorization': f'Bearer {token}'})
        response.raise_for_status()
