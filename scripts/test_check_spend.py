"""Unit tests for :mod:`check_spend` (v12-N-7).

Run with ``python -m pytest scripts/test_check_spend.py``.
"""

from __future__ import annotations

import unittest

from check_spend import project_total_spend, should_abort, main


class ProjectTotalSpendTests(unittest.TestCase):
    def test_linear_extrapolation_at_half_complete(self) -> None:
        # 1 hour at $2/hr with half the work done → projected total $4.
        self.assertAlmostEqual(
            project_total_spend(3600.0, 0.5, 2.0), 4.0, places=6
        )

    def test_completion_returns_spent_so_far(self) -> None:
        # fraction_complete == 1 → projection equals spent so far.
        self.assertAlmostEqual(
            project_total_spend(7200.0, 1.0, 3.0), 6.0, places=6
        )

    def test_zero_elapsed_returns_zero(self) -> None:
        self.assertAlmostEqual(project_total_spend(0.0, 0.5, 10.0), 0.0)

    def test_zero_hourly_returns_zero(self) -> None:
        self.assertAlmostEqual(project_total_spend(7200.0, 0.5, 0.0), 0.0)

    def test_quarter_complete_quadruples_spent(self) -> None:
        # $2 spent at 25 % done → $8 projected.
        self.assertAlmostEqual(
            project_total_spend(3600.0, 0.25, 2.0), 8.0, places=6
        )

    def test_rejects_negative_elapsed(self) -> None:
        with self.assertRaises(ValueError):
            project_total_spend(-1.0, 0.5, 2.0)

    def test_rejects_zero_fraction(self) -> None:
        with self.assertRaises(ValueError):
            project_total_spend(3600.0, 0.0, 2.0)

    def test_rejects_fraction_above_one(self) -> None:
        with self.assertRaises(ValueError):
            project_total_spend(3600.0, 1.5, 2.0)

    def test_rejects_negative_hourly(self) -> None:
        with self.assertRaises(ValueError):
            project_total_spend(3600.0, 0.5, -1.0)


class ShouldAbortTests(unittest.TestCase):
    def test_max_usd_zero_always_aborts(self) -> None:
        self.assertTrue(should_abort(0.0, 1.0, 2.0, max_usd=0.0))
        self.assertTrue(should_abort(3600.0, 0.5, 2.0, max_usd=0.0))

    def test_projection_under_ceiling_does_not_abort(self) -> None:
        # $4 projected, $5 ceiling.
        self.assertFalse(should_abort(3600.0, 0.5, 2.0, max_usd=5.0))

    def test_projection_at_ceiling_does_not_abort(self) -> None:
        # Exact match is allowed.
        self.assertFalse(should_abort(3600.0, 0.5, 2.0, max_usd=4.0))

    def test_projection_above_ceiling_aborts(self) -> None:
        self.assertTrue(should_abort(3600.0, 0.5, 2.0, max_usd=3.99))

    def test_rejects_negative_max(self) -> None:
        with self.assertRaises(ValueError):
            should_abort(0.0, 1.0, 1.0, max_usd=-1.0)


class CliTests(unittest.TestCase):
    def test_cli_ok_exit_zero(self) -> None:
        rc = main(
            [
                "--elapsed-seconds",
                "3600",
                "--fraction-complete",
                "0.5",
                "--hourly-usd",
                "2",
                "--max-usd",
                "10",
            ]
        )
        self.assertEqual(rc, 0)

    def test_cli_abort_exit_one(self) -> None:
        rc = main(
            [
                "--elapsed-seconds",
                "3600",
                "--fraction-complete",
                "0.5",
                "--hourly-usd",
                "2",
                "--max-usd",
                "3",
            ]
        )
        self.assertEqual(rc, 1)

    def test_cli_dry_run_max_usd_zero_aborts(self) -> None:
        rc = main(
            [
                "--elapsed-seconds",
                "1",
                "--fraction-complete",
                "1",
                "--hourly-usd",
                "1",
                "--max-usd",
                "0",
            ]
        )
        self.assertEqual(rc, 1)

    def test_cli_invalid_input_exit_two(self) -> None:
        rc = main(
            [
                "--elapsed-seconds",
                "-1",
                "--fraction-complete",
                "0.5",
                "--hourly-usd",
                "2",
                "--max-usd",
                "10",
            ]
        )
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
