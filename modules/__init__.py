# SupaHunt modules
from .base import BaseModule, RateLimiter, RetryConfig
from .discovery import SupabaseTarget, Discovery, decode_jwt_payload
from .discovery_v2 import DiscoveryV2
from .enumerator import Enumerator, TableInfo, StorageBucket
from .exploiter import (
    AuthExploiter, DataExploiter, RPCExploiter,
    PersistenceExploiter, ProfileExploiter,
)
from .graphql_tester import GraphQLMutationTester, MutationResult
from .storage_exploiter import StorageExploiter, BucketInfo
from .filter_injection import FilterInjectionTester, FilterInjectionResult
from .reporter import ScanReport, Finding
# v2 modules — advanced exploitation
from .webhook_poisoner import WebhookPoisoner
from .review_injector import ReviewInjector
from .rpc_abuser import RPCAbuser
from .token_forger import TokenForger
