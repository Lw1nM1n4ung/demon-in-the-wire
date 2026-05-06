"""Tests for discovery helper functions — CIDR partitioning and range expansion."""

from __future__ import annotations

import ipaddress

from wireghost.pipeline.discovery import _partition_target, _range_to_cidrs


# ================================================================
# _range_to_cidrs
# ================================================================


class TestRangeToCidrs:
    def test_simple_range(self):
        result = _range_to_cidrs("10.0.0.0-10.0.0.255")
        assert result is not None
        assert len(result) == 1
        assert result[0] == ipaddress.IPv4Network("10.0.0.0/24")

    def test_larger_range(self):
        result = _range_to_cidrs("10.0.0.0-10.0.3.255")
        assert result is not None
        total_ips = sum(net.num_addresses for net in result)
        assert total_ips == 1024

    def test_single_ip_range(self):
        result = _range_to_cidrs("10.0.0.1-10.0.0.1")
        assert result is not None
        assert len(result) == 1
        assert result[0] == ipaddress.IPv4Network("10.0.0.1/32")

    def test_reversed_range_returns_none(self):
        result = _range_to_cidrs("10.0.0.255-10.0.0.0")
        assert result is None

    def test_no_dash_returns_none(self):
        result = _range_to_cidrs("10.0.0.0/24")
        assert result is None

    def test_invalid_ip_returns_none(self):
        result = _range_to_cidrs("999.999.999.999-10.0.0.1")
        assert result is None

    def test_hostname_returns_none(self):
        result = _range_to_cidrs("example.com")
        assert result is None


# ================================================================
# _partition_target
# ================================================================


class TestPartitionTarget:
    def test_slash_24_no_split(self):
        result = _partition_target("10.0.0.0/24")
        assert result == ["10.0.0.0/24"]

    def test_slash_25_no_split(self):
        result = _partition_target("10.0.0.0/25")
        assert result == ["10.0.0.0/25"]

    def test_slash_32_no_split(self):
        result = _partition_target("10.0.0.1/32")
        assert result == ["10.0.0.1/32"]

    def test_single_ip(self):
        result = _partition_target("10.0.0.1")
        assert result == ["10.0.0.1"]

    def test_slash_16_splits_to_256(self):
        result = _partition_target("10.0.0.0/16")
        assert len(result) == 256
        assert all("/24" in s for s in result)

    def test_slash_20_splits_to_16(self):
        result = _partition_target("10.0.0.0/20")
        assert len(result) == 16

    def test_slash_23_splits_to_2(self):
        result = _partition_target("10.0.0.0/23")
        assert len(result) == 2
        assert result[0] == "10.0.0.0/24"
        assert result[1] == "10.0.1.0/24"

    def test_hostname_returned_as_is(self):
        result = _partition_target("example.com")
        assert result == ["example.com"]

    def test_dash_range_partitioned(self):
        result = _partition_target("10.0.0.0-10.0.3.255")
        assert len(result) == 4
        assert all("/24" in s for s in result)

    def test_small_dash_range_no_split(self):
        result = _partition_target("10.0.0.0-10.0.0.255")
        assert len(result) == 1

    def test_all_subnets_valid_cidrs(self):
        result = _partition_target("172.16.0.0/16")
        for cidr in result:
            net = ipaddress.ip_network(cidr, strict=False)
            assert net.prefixlen == 24
