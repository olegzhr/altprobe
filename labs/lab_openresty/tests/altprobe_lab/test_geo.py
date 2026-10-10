import json
import unittest

from . import common
from . import suricata_events as se


@unittest.skipUnless(common.redis_available(), "Redis is not reachable")
class GeoMap(unittest.TestCase):
    """Verifies the Suricata netflow path enriches endpoints with GeoIP data
    from the lab's test-only MaxMind-compatible database."""

    def test_netflow_has_multiple_geo_locations(self):
        common.redis_del(common.LAB_REDIS_KEY)
        pairs = [
            (se.SRC_US, se.DST_NL),
            (se.SRC_DE, se.DST_JP),
            (se.SRC_SG, se.DST_IN),
            (se.SRC_AU, se.DST_NL),
            (se.SRC_BR, se.DST_JP),
        ]
        for index, (src, dst) in enumerate(pairs):
            common.redis_push(common.LAB_REDIS_KEY, json.dumps(
                se.netflow_event(src=src, dst=dst, flow_id=5000 + index)))

        located = common.wait_for(
            lambda: common.os_count(common.OSCF["network"],
                                    {"exists": {"field": "src_endpoint.location.coordinates"}}) > 0,
            timeout=30)
        self.assertTrue(located, "no 4005 netflow documents carry GeoIP coordinates")

        def countries():
            result = common.os_search(common.OSCF["network"], {
                "size": 0,
                "query": {"exists": {"field": "src_endpoint.location.country"}},
                "aggs": {"countries": {"terms": {"field": "src_endpoint.location.country"}}},
            })
            return result.get("aggregations", {}).get("countries", {}).get("buckets", [])

        # OpenSearch indexing is near-real-time: wait until all emitted
        # locations are visible before asserting the aggregate.
        common.wait_for(lambda: len(countries()) >= 2, timeout=30)
        buckets = countries()
        self.assertGreaterEqual(len(buckets), 2,
                                "expected netflow from multiple countries, got %r" % buckets)
