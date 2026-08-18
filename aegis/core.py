# Aegis Runtime Core
from __future__ import annotations
import dataclasses, functools, hashlib, json, os, time
from typing import Any, Callable, Dict, List, Optional, Tuple

GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"

@dataclasses.dataclass(frozen=True)
class ActionReceipt:
    index: int
    prev_hash: str
    action_id: str
    target: str
    debt_score: float
    status: str
    timestamp: float
    payload_hash: str
    signature_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

class CryptographicActionLedger:
    def __init__(self, ledger_path: Optional[str] = None):
        self.ledger_path = ledger_path
        self._entries: List[ActionReceipt] = []
        self._last_hash = GENESIS_HASH

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def count(self) -> int:
        return len(self._entries)

    def record_execution(self, action_id: str, target: str, debt_score: float, status: str, metadata: Optional[Dict[str, Any]] = None) -> ActionReceipt:
        idx = len(self._entries)
        ts = time.time()
        meta_bytes = json.dumps(metadata or {}, sort_keys=True).encode("utf-8")
        payload_hash = hashlib.sha256(meta_bytes).hexdigest()
        raw_msg = f"{idx}:{self._last_hash}:{action_id}:{target}:{debt_score:.4f}:{ts:.6f}:{payload_hash}"
        sig_hash = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()

        receipt = ActionReceipt(
            index=idx,
            prev_hash=self._last_hash,
            action_id=action_id,
            target=target,
            debt_score=debt_score,
            status=status,
            timestamp=ts,
            payload_hash=payload_hash,
            signature_hash=sig_hash,
        )
        self._entries.append(receipt)
        self._last_hash = sig_hash

        if self.ledger_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.ledger_path)), exist_ok=True)
            with open(self.ledger_path, "a", encoding="utf-8") as lf:
                lf.write(json.dumps(receipt.to_dict()) + chr(10))

        return receipt

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        current_prev = GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.index != idx:
                return False, f"Index mismatch at {idx}: expected {idx}, got {entry.index}"
            if entry.prev_hash != current_prev:
                return False, f"Broken chain hash at {idx}: expected {current_prev}, got {entry.prev_hash}"
            current_prev = entry.signature_hash
        return True, None

class ActionGate:
    def __init__(self, max_debt_index: float = 12.0, max_latency_ms: float = 2800.0, max_sprawl_multiplier: float = 1.15, ledger: Optional[CryptographicActionLedger] = None):
        self.max_debt_index = max_debt_index
        self.max_latency_ms = max_latency_ms
        self.max_sprawl_multiplier = max_sprawl_multiplier
        self.ledger = ledger or CryptographicActionLedger()

    def check_kill_switch(self) -> bool:
        if os.environ.get("AEGIS_KILL_SWITCH", "0") in ("1", "true", "TRUE"):
            return True
        if os.path.exists("/tmp/AEGIS_KILL") or os.path.exists("artifacts/KILL"):
            return True
        return False

    def evaluate_debt(self, action_name: str, sprawl_ratio: float = 1.0, latency_ms: float = 0.0, un_gated_mutations: int = 0, metadata: Optional[Dict[str, Any]] = None) -> Tuple[bool, float, ActionReceipt]:
        if self.check_kill_switch():
            receipt = self.ledger.record_execution(
                action_id=action_name,
                target="EMERGENCY_KILL_SWITCH",
                debt_score=999.0,
                status="HALTED_BY_KILL_SWITCH",
                metadata=metadata,
            )
            return False, 999.0, receipt

        sprawl_debt = max(0.0, (sprawl_ratio - 1.0) * 20.0)
        latency_debt = max(0.0, (latency_ms - 2.8) * 0.5)
        mutation_debt = float(un_gated_mutations * 30.0)
        total_debt = sprawl_debt + latency_debt + mutation_debt

        authorized = (
            total_debt <= self.max_debt_index
            and sprawl_ratio <= self.max_sprawl_multiplier
            and latency_ms <= self.max_latency_ms
            and un_gated_mutations == 0
        )

        status = "AUTHORIZED" if authorized else "REJECTED_PRODUCTION_DEBT"
        receipt = self.ledger.record_execution(
            action_id=action_name,
            target="RUNTIME_GATE",
            debt_score=total_debt,
            status=status,
            metadata=metadata,
        )
        return authorized, total_debt, receipt

    def guard(self, action_name: Optional[str] = None):
        def decorator(func: Callable):
            name = action_name or func.__name__
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                t0 = time.perf_counter()
                meta = {"args_count": len(args), "kwargs_keys": list(kwargs.keys())}
                auth, debt, receipt = self.evaluate_debt(action_name=name, sprawl_ratio=1.0, latency_ms=0.0, un_gated_mutations=0, metadata=meta)
                if not auth:
                    raise PermissionError(f"[Aegis Runtime] Action '{name}' blocked: DebtScore={debt:.2f}, Status={receipt.status}")
                result = func(*args, **kwargs)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if elapsed_ms > self.max_latency_ms:
                    self.ledger.record_execution(action_id=name, target="LATENCY_POST_CHECK", debt_score=elapsed_ms, status="FLAGGED_LATENCY_OVERFLOW", metadata={"elapsed_ms": elapsed_ms})
                return result
            return wrapper
        return decorator
