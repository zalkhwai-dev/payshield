"""Minimal PayPal Orders v2 client for the SANDBOX environment."""

import os
import time

import requests

PAYPAL_BASE = os.getenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
_token_cache = {"token": None, "expires": 0}


def is_configured() -> bool:
    return bool(os.getenv("PAYPAL_CLIENT_ID") and os.getenv("PAYPAL_CLIENT_SECRET"))


def _access_token() -> str:
    if _token_cache["token"] and time.time() < _token_cache["expires"] - 60:
        return _token_cache["token"]
    r = requests.post(
        f"{PAYPAL_BASE}/v1/oauth2/token",
        auth=(os.environ["PAYPAL_CLIENT_ID"], os.environ["PAYPAL_CLIENT_SECRET"]),
        data={"grant_type": "client_credentials"},
        timeout=20,
    )
    r.raise_for_status()
    data = r.json()
    _token_cache.update(token=data["access_token"], expires=time.time() + data.get("expires_in", 3000))
    return data["access_token"]


def create_order(amount: float, currency: str, description: str, check_id: str) -> dict:
    r = requests.post(
        f"{PAYPAL_BASE}/v2/checkout/orders",
        headers={"Authorization": f"Bearer {_access_token()}", "Content-Type": "application/json",
                 "PayPal-Request-Id": f"payshield-{check_id}"},
        json={
            "intent": "CAPTURE",
            "purchase_units": [{
                "amount": {"currency_code": currency, "value": f"{amount:.2f}"},
                "description": description[:127],
                "custom_id": f"payshield:{check_id}",
            }],
        },
        timeout=20,
    )
    r.raise_for_status()
    return r.json()


def capture_order(order_id: str) -> dict:
    r = requests.post(
        f"{PAYPAL_BASE}/v2/checkout/orders/{order_id}/capture",
        headers={"Authorization": f"Bearer {_access_token()}", "Content-Type": "application/json"},
        timeout=20,
    )
    r.raise_for_status()
    return r.json()
