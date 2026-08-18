import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from aegis.core import ActionGate, CryptographicActionLedger, GENESIS_HASH


class TestAegisRuntime(unittest.TestCase):
    def setUp(self):
        self.ledger = CryptographicActionLedger()
        self.gate = ActionGate(ledger=self.ledger)

    def test_cryptographic_chain_integrity(self):
        self.gate.evaluate_debt('agent_db_read', sprawl_ratio=1.02, latency_ms=1.2)
        self.gate.evaluate_debt('agent_sql_mutate', sprawl_ratio=1.04, latency_ms=2.1)
        self.gate.evaluate_debt('agent_tool_exec', sprawl_ratio=1.01, latency_ms=0.8)

        self.assertEqual(self.ledger.count, 3)
        valid, err = self.ledger.verify_chain_integrity()
        self.assertTrue(valid, f'Ledger chain verification failed: {err}')
        self.assertNotEqual(self.ledger.last_hash, GENESIS_HASH)

    def test_production_debt_blocking(self):
        # Sprawl ratio exceeds threshold (1.80 > 1.15) -> ADI explodes
        auth, debt, receipt = self.gate.evaluate_debt('leaky_agent_tool', sprawl_ratio=1.80, latency_ms=10.0)
        self.assertFalse(auth)
        self.assertEqual(receipt.status, 'REJECTED_PRODUCTION_DEBT')
        self.assertGreater(debt, 12.0)

    def test_decorator_guard(self):
        @self.gate.guard('secure_computation')
        def calculate_risk(base_val: float):
            return base_val * 2.5

        result = calculate_risk(10.0)
        self.assertEqual(result, 25.0)
        self.assertEqual(self.ledger.count, 1)


if __name__ == '__main__':
    unittest.main()
