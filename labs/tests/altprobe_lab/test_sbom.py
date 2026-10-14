import unittest

from . import common


class SbomFindings(unittest.TestCase):
    """Verifies that the SBOM scanner turns the CycloneDX fixture into OCSF
    2002 Vulnerability Finding documents."""

    def test_vulnerability_findings_indexed(self):
        indexed = common.wait_for(
            lambda: common.os_count(common.OSCF["vulnerability"]) > 0, timeout=90)
        self.assertTrue(indexed, "no OCSF 2002 findings; is the SBOM scanner enabled?")

        total = common.os_count(common.OSCF["vulnerability"])
        self.assertGreaterEqual(total, 3, "expected at least 3 CVE findings, got %s" % total)

        result = common.os_search(common.OSCF["vulnerability"], {
            "size": 50,
            "query": {"match_all": {}},
            "_source": ["vulnerability.uid", "severity"],
        })
        uids = {
            hit.get("_source", {}).get("vulnerability", {}).get("uid")
            for hit in result.get("hits", {}).get("hits", [])
        }
        self.assertIn("CVE-2021-44228", uids, "expected the bundled fixture CVE ids, got %r" % uids)
