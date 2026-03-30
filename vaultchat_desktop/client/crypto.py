from __future__ import annotations

import hashlib
import hmac
import os
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shared.protocol import b64d, b64e, canonical_json

BOOTSTRAP_ADMIN_HASH = hashlib.sha256(b'admin').hexdigest()
GROUP_CONTEXT = b'vaultchat-group-v1'
DM_CONTEXT = b'vaultchat-dm-v1'


def verify_bootstrap_admin(password: str) -> bool:
    candidate = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hmac.compare_digest(candidate, BOOTSTRAP_ADMIN_HASH)


def generate_identity() -> Dict[str, str]:
    enc_priv = x25519.X25519PrivateKey.generate()
    sign_priv = ed25519.Ed25519PrivateKey.generate()
    return {
        'enc_private': b64e(
            enc_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ),
        'enc_public': b64e(
            enc_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
        'sign_private': b64e(
            sign_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ),
        'sign_public': b64e(
            sign_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
    }


def _load_x25519_private(b64: str) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(b64d(b64))


def _load_x25519_public(b64: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b64d(b64))


def _load_ed25519_private(b64: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(b64))


def _load_ed25519_public(b64: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(b64))


def derive_group_key(group_secret: str, group_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(group_id.encode('utf-8')).digest(),
        info=GROUP_CONTEXT,
    )
    return hkdf.derive(group_secret.encode('utf-8'))


def encrypt_group_message(*, plaintext: str, group_secret: str, group_id: str, sender_user_id: str, sender_sign_private_b64: str) -> Dict[str, str]:
    key = derive_group_key(group_secret, group_id)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    aad = canonical_json({'kind': 'group', 'group_id': group_id, 'sender_user_id': sender_user_id})
    ciphertext = aes.encrypt(nonce, plaintext.encode('utf-8'), aad)
    body = {
        'kind': 'group',
        'group_id': group_id,
        'sender_user_id': sender_user_id,
        'nonce': b64e(nonce),
        'ciphertext': b64e(ciphertext),
    }
    signer = _load_ed25519_private(sender_sign_private_b64)
    body['signature'] = b64e(signer.sign(canonical_json(body)))
    return body


def decrypt_group_message(*, envelope: Dict[str, str], group_secret: str, group_id: str, sender_sign_public_b64: str) -> str:
    verifier = _load_ed25519_public(sender_sign_public_b64)
    signed = dict(envelope)
    signature = signed.pop('signature')
    verifier.verify(b64d(signature), canonical_json(signed))
    key = derive_group_key(group_secret, group_id)
    aes = AESGCM(key)
    aad = canonical_json({'kind': 'group', 'group_id': group_id, 'sender_user_id': envelope['sender_user_id']})
    return aes.decrypt(b64d(envelope['nonce']), b64d(envelope['ciphertext']), aad).decode('utf-8')


def _encrypt_dm_copy(plaintext: str, sender_user_id: str, recipient_user_id: str, recipient_enc_public_b64: str) -> Dict[str, str]:
    eph_priv = x25519.X25519PrivateKey.generate()
    recipient_pub = _load_x25519_public(recipient_enc_public_b64)
    shared_secret = eph_priv.exchange(recipient_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(f'{sender_user_id}|{recipient_user_id}'.encode('utf-8')).digest(),
        info=DM_CONTEXT,
    )
    key = hkdf.derive(shared_secret)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    aad = canonical_json({'kind': 'dm', 'sender_user_id': sender_user_id, 'recipient_user_id': recipient_user_id})
    ciphertext = aes.encrypt(nonce, plaintext.encode('utf-8'), aad)
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        'ephemeral_public': b64e(eph_pub),
        'nonce': b64e(nonce),
        'ciphertext': b64e(ciphertext),
    }


def encrypt_dm_message(*, plaintext: str, sender_user_id: str, recipient_user_id: str, recipient_enc_public_b64: str, sender_enc_public_b64: str, sender_sign_private_b64: str) -> Dict[str, str]:
    recipient_copy = _encrypt_dm_copy(plaintext, sender_user_id, recipient_user_id, recipient_enc_public_b64)
    sender_copy = _encrypt_dm_copy(plaintext, sender_user_id, sender_user_id, sender_enc_public_b64)
    body = {
        'kind': 'dm',
        'sender_user_id': sender_user_id,
        'recipient_user_id': recipient_user_id,
        'recipient_ephemeral_public': recipient_copy['ephemeral_public'],
        'recipient_nonce': recipient_copy['nonce'],
        'recipient_ciphertext': recipient_copy['ciphertext'],
        'sender_copy_ephemeral_public': sender_copy['ephemeral_public'],
        'sender_copy_nonce': sender_copy['nonce'],
        'sender_copy_ciphertext': sender_copy['ciphertext'],
    }
    signer = _load_ed25519_private(sender_sign_private_b64)
    body['signature'] = b64e(signer.sign(canonical_json(body)))
    return body


def decrypt_dm_message(*, envelope: Dict[str, str], current_user_id: str, recipient_enc_private_b64: str, sender_sign_public_b64: str) -> str:
    verifier = _load_ed25519_public(sender_sign_public_b64)
    signed = dict(envelope)
    signature = signed.pop('signature')
    verifier.verify(b64d(signature), canonical_json(signed))

    if current_user_id == envelope['sender_user_id']:
        eph_key = 'sender_copy_ephemeral_public'
        nonce_key = 'sender_copy_nonce'
        ct_key = 'sender_copy_ciphertext'
        recipient_id_for_kdf = envelope['sender_user_id']
    else:
        eph_key = 'recipient_ephemeral_public'
        nonce_key = 'recipient_nonce'
        ct_key = 'recipient_ciphertext'
        recipient_id_for_kdf = envelope['recipient_user_id']

    recipient_priv = _load_x25519_private(recipient_enc_private_b64)
    eph_pub = _load_x25519_public(envelope[eph_key])
    shared_secret = recipient_priv.exchange(eph_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(f"{envelope['sender_user_id']}|{recipient_id_for_kdf}".encode('utf-8')).digest(),
        info=DM_CONTEXT,
    )
    key = hkdf.derive(shared_secret)
    aes = AESGCM(key)
    aad = canonical_json({'kind': 'dm', 'sender_user_id': envelope['sender_user_id'], 'recipient_user_id': recipient_id_for_kdf})
    return aes.decrypt(b64d(envelope[nonce_key]), b64d(envelope[ct_key]), aad).decode('utf-8')


def verify_local_admin_password(stored_hash: str, password: str) -> bool:
    candidate = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hmac.compare_digest(stored_hash, candidate)


def hash_local_admin_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()
