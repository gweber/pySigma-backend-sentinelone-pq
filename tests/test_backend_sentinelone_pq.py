import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sentinelone_pq import SentinelOnePQBackend

@pytest.fixture
def sentinelone_pq_backend():
    return SentinelOnePQBackend()

def test_sentinelone_pq_and_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                    ParentImage: valueB
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and (tgt.process.image.path in:anycase ("valueA") and src.process.image.path in:anycase ("valueB"))']

def test_sentinelone_pq_or_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA
                sel2:
                    ParentImage: valueB
                condition: 1 of sel*
        """)
    ) == ['event.type in:anycase ("Process Creation") and (tgt.process.image.path in:anycase ("valueA") or src.process.image.path in:anycase ("valueB"))']

def test_sentinelone_pq_and_or_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA1
                        - valueA2
                    ParentImage:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and ((tgt.process.image.path in:anycase ("valueA1","valueA2")) and (src.process.image.path in:anycase ("valueB1","valueB2")))']

def test_sentinelone_pq_or_and_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA1
                    ParentImage: valueB1
                sel2:
                    Image: valueA2
                    ParentImage: valueB2
                condition: 1 of sel*
        """)
    ) == ['event.type in:anycase ("Process Creation") and ((tgt.process.image.path in:anycase ("valueA1") and src.process.image.path in:anycase ("valueB1")) or (tgt.process.image.path in:anycase ("valueA2") and src.process.image.path in:anycase ("valueB2")))']

def test_sentinelone_pq_in_expression(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and (tgt.process.image.path in:anycase ("valueA") or tgt.process.image.path in:anycase ("valueB") or tgt.process.image.path matches "^valueC")']

def test_sentinelone_pq_regex_query(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image|re: foo.*bar
                    ParentImage: foo
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and (tgt.process.image.path matches "foo.*bar" and src.process.image.path in:anycase ("foo"))']

def test_sentinelone_pq_cidr_query(sentinelone_pq_backend : SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    DestinationIp|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['event.category in:anycase ("ip") and dst.ip.address matches "^192\\\\.168\\\\."']

def test_sentinelone_pq_escape_char_query(sentinelone_pq_backend: SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: Test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image|startswith: C:\\Windows\\System32\\
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and tgt.process.image.path matches "^C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\"']

def test_sentinelone_pq_default_output(sentinelone_pq_backend : SentinelOnePQBackend):
    """Test for output format default."""
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and tgt.process.image.path in:anycase ("valueA")']

def test_sentinelone_pq_json_output(sentinelone_pq_backend : SentinelOnePQBackend):
    """Test for output format default."""
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """), "json"
    ) == {"queries":[{"query":'event.type in:anycase ("Process Creation") and tgt.process.image.path in:anycase ("valueA")', "title":"Test", "id":None, "description":None}]}




def test_sentinelone_pq_wildcard_inside_value(sentinelone_pq_backend: SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    CommandLine: 'a(b)*c'
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and tgt.process.cmdline matches "^a\\\\(b\\\\).*c$"']

def test_sentinelone_pq_endswith_is_anchored(sentinelone_pq_backend: SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image|endswith: '\\svchost.exe'
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and tgt.process.image.path matches "\\\\\\\\svchost\\\\.exe$"']

def test_sentinelone_pq_regex_with_double_quote(sentinelone_pq_backend: SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    CommandLine|re: 'tool\\.bat" --list'
                condition: sel
        """)
    ) == ['event.type in:anycase ("Process Creation") and tgt.process.cmdline matches "tool\\\\.bat\\" --list"']

def test_sentinelone_pq_not_single_comparison_grouped(sentinelone_pq_backend: SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                filter:
                    CommandLine|contains: valueB
                condition: sel and not filter
        """)
    ) == ['event.type in:anycase ("Process Creation") and (tgt.process.image.path in:anycase ("valueA") and (not (tgt.process.cmdline contains "valueB")))']

CORRELATION_BASE = """
title: Renamed with an extension
id: 0e95725d-7320-415d-80f7-004da920fc11
name: renamed
status: test
logsource:
    category: file_rename
    product: test_product
detection:
    sel:
        TargetFilename|contains: '.locked'
    condition: sel
---
"""

def test_sentinelone_pq_event_count_correlation(sentinelone_pq_backend: SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(SigmaCollection.from_yaml(CORRELATION_BASE + """
title: Many renames
status: test
correlation:
    type: event_count
    rules: [renamed]
    group-by: [Image]
    timespan: 5m
    condition:
        gte: 100
"""))[-1] == ('event.type in:anycase ("File Rename") and tgt.file.path contains ".locked" '
              "| group event_count = count() by timebucket = timebucket('5m'), src.process.image.path "
              "| filter event_count >= 100")

def test_sentinelone_pq_value_count_correlation_is_exact(sentinelone_pq_backend: SentinelOnePQBackend):
    assert sentinelone_pq_backend.convert(SigmaCollection.from_yaml(CORRELATION_BASE + """
title: Many files renamed
status: test
correlation:
    type: value_count
    rules: [renamed]
    group-by: [Image]
    timespan: 1h
    condition:
        field: TargetFilename
        gte: 50
"""))[-1] == ('event.type in:anycase ("File Rename") and tgt.file.path contains ".locked" '
              "| group events = count() by timebucket = timebucket('1h'), src.process.image.path, tgt.file.path "
              "| group value_count = count() by timebucket, src.process.image.path | filter value_count >= 50")

def test_sentinelone_pq_temporal_correlation_is_refused(sentinelone_pq_backend: SentinelOnePQBackend):
    with pytest.raises(Exception):
        sentinelone_pq_backend.convert(SigmaCollection.from_yaml(CORRELATION_BASE + """
title: Renamed then renamed
status: test
correlation:
    type: temporal
    rules: [renamed]
    group-by: [Image]
    timespan: 5m
"""))
