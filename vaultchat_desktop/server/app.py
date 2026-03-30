from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from server.db import Database
from shared.protocol import BOOTSTRAP_ADMIN_PASSWORD, random_code, utc_now_iso

app = FastAPI(title='VaultChat Relay Server')
db = Database()
active_websockets: Dict[str, List[WebSocket]] = {}
BOOTSTRAP_HASH = hashlib.sha256(BOOTSTRAP_ADMIN_PASSWORD.encode('utf-8')).hexdigest()


class CreateGroupRequest(BaseModel):
    bootstrap_password: str
    display_name: str = Field(min_length=2, max_length=32)
    group_name: str = Field(min_length=2, max_length=64)
    enc_public: str
    sign_public: str


class JoinGroupRequest(BaseModel):
    group_secret: str
    display_name: str = Field(min_length=2, max_length=32)
    enc_public: str
    sign_public: str


class GroupMessageRequest(BaseModel):
    envelope: Dict[str, Any]


class DmMessageRequest(BaseModel):
    recipient_user_id: str
    envelope: Dict[str, Any]


@app.get('/health')
def health() -> Dict[str, str]:
    return {'status': 'ok'}


def _auth_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Missing bearer token')
    return authorization.split(' ', 1)[1].strip()


def _current_user(authorization: str | None) -> Dict[str, Any]:
    token = _auth_token(authorization)
    user = db.get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid token')
    return user


async def _broadcast_targets(user_ids: set[str], payload: Dict[str, Any]) -> None:
    for user_id in user_ids:
        sockets = active_websockets.get(user_id, [])
        dead: List[WebSocket] = []
        for ws in sockets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        if dead:
            active_websockets[user_id] = [ws for ws in sockets if ws not in dead]


@app.post('/bootstrap/create-group')
def create_group(request: CreateGroupRequest) -> Dict[str, Any]:
    if db.group_exists():
        raise HTTPException(status_code=409, detail='A group already exists on this server')
    candidate = hashlib.sha256(request.bootstrap_password.encode('utf-8')).hexdigest()
    if not hmac.compare_digest(candidate, BOOTSTRAP_HASH):
        raise HTTPException(status_code=403, detail='Invalid bootstrap password')

    group_id = str(uuid4())
    admin_user_id = str(uuid4())
    token = secrets.token_urlsafe(32)
    group_secret = random_code(32)
    created_at = utc_now_iso()
    secret_hash = hashlib.sha256(group_secret.encode('utf-8')).hexdigest()

    db.create_group(group_id=group_id, name=request.group_name, secret_hash=secret_hash, admin_user_id=admin_user_id, created_at=created_at)
    db.create_user(user_id=admin_user_id, display_name=request.display_name, enc_public=request.enc_public, sign_public=request.sign_public, is_admin=True, group_id=group_id, token=token, created_at=created_at)
    return {
        'user_id': admin_user_id,
        'token': token,
        'group_id': group_id,
        'group_name': request.group_name,
        'group_secret': group_secret,
        'is_admin': True,
    }


@app.post('/group/join')
def join_group(request: JoinGroupRequest) -> Dict[str, Any]:
    secret_hash = hashlib.sha256(request.group_secret.encode('utf-8')).hexdigest()
    group = db.find_group_by_secret_hash(secret_hash)
    if not group:
        raise HTTPException(status_code=403, detail='Invalid group secret')
    existing_names = {u['display_name'].lower() for u in db.list_members(group['id'])}
    if request.display_name.lower() in existing_names:
        raise HTTPException(status_code=409, detail='Display name already exists in this group')

    user_id = str(uuid4())
    token = secrets.token_urlsafe(32)
    created_at = utc_now_iso()
    db.create_user(user_id=user_id, display_name=request.display_name, enc_public=request.enc_public, sign_public=request.sign_public, is_admin=False, group_id=group['id'], token=token, created_at=created_at)
    return {
        'user_id': user_id,
        'token': token,
        'group_id': group['id'],
        'group_name': group['name'],
        'group_secret': request.group_secret,
        'is_admin': False,
    }


@app.get('/group/members')
def group_members(authorization: str | None = Header(default=None, alias='Authorization')) -> Dict[str, Any]:
    user = _current_user(authorization)
    return {'members': db.list_members(user['group_id'])}


@app.get('/messages/group')
def group_messages(authorization: str | None = Header(default=None, alias='Authorization')) -> Dict[str, Any]:
    user = _current_user(authorization)
    return {'messages': db.list_group_messages(user['group_id'])}


@app.post('/messages/group')
async def send_group_message(request: GroupMessageRequest, authorization: str | None = Header(default=None, alias='Authorization')) -> Dict[str, Any]:
    user = _current_user(authorization)
    envelope = request.envelope
    if envelope.get('sender_user_id') != user['id'] or envelope.get('group_id') != user['group_id']:
        raise HTTPException(status_code=400, detail='Envelope identity mismatch')
    message_id = str(uuid4())
    created_at = utc_now_iso()
    db.create_group_message(message_id=message_id, group_id=user['group_id'], sender_user_id=user['id'], envelope=envelope, created_at=created_at)
    await _broadcast_targets({m['id'] for m in db.list_members(user['group_id'])}, {
        'event': 'group_message',
        'message': {'id': message_id, 'group_id': user['group_id'], 'sender_user_id': user['id'], 'envelope': envelope, 'created_at': created_at},
    })
    return {'status': 'ok'}


@app.get('/messages/dm/{other_user_id}')
def dm_messages(other_user_id: str, authorization: str | None = Header(default=None, alias='Authorization')) -> Dict[str, Any]:
    user = _current_user(authorization)
    other = db.get_user(other_user_id)
    if not other or other['group_id'] != user['group_id']:
        raise HTTPException(status_code=404, detail='User not found in your group')
    return {'messages': db.list_dm_messages(user['id'], other_user_id)}


@app.post('/messages/dm')
async def send_dm_message(request: DmMessageRequest, authorization: str | None = Header(default=None, alias='Authorization')) -> Dict[str, Any]:
    user = _current_user(authorization)
    recipient = db.get_user(request.recipient_user_id)
    if not recipient or recipient['group_id'] != user['group_id']:
        raise HTTPException(status_code=404, detail='Recipient not found in your group')
    envelope = request.envelope
    if envelope.get('sender_user_id') != user['id'] or envelope.get('recipient_user_id') != recipient['id']:
        raise HTTPException(status_code=400, detail='Envelope identity mismatch')
    message_id = str(uuid4())
    created_at = utc_now_iso()
    db.create_dm_message(message_id=message_id, sender_user_id=user['id'], recipient_user_id=recipient['id'], envelope=envelope, created_at=created_at)
    await _broadcast_targets({recipient['id'], user['id']}, {
        'event': 'dm_message',
        'message': {'id': message_id, 'sender_user_id': user['id'], 'recipient_user_id': recipient['id'], 'envelope': envelope, 'created_at': created_at},
    })
    return {'status': 'ok'}


@app.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket, token: str) -> None:
    user = db.get_user_by_token(token)
    if not user:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    active_websockets.setdefault(user['id'], []).append(websocket)
    try:
        await websocket.send_json({'event': 'connected', 'user_id': user['id']})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        sockets = active_websockets.get(user['id'], [])
        active_websockets[user['id']] = [ws for ws in sockets if ws is not websocket]
