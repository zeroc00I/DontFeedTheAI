"""
Unit tests for StreamingDeanonymizer — boundary-safe incremental de-anonymization.

The proxy streams Claude's response token-by-token. Surrogates (e.g. "SRV-1042")
can arrive split across two SSE deltas ("SRV-10" + "42"). The de-anonymizer must
never emit a partial/undeanonymized surrogate, yet must produce output identical
to a full-buffer deanonymize() once the stream completes.
"""
import pytest

from src.anonymizer import StreamingDeanonymizer


def _batch_replace(mappings, text):
    """Reference: what the existing full-buffer deanonymize does."""
    for surrogate, original in mappings:
        if surrogate in text:
            text = text.replace(surrogate, original)
    return text


class TestSingleDelta:
    def test_surrogate_fully_within_one_delta_is_deanonymized(self):
        sd = StreamingDeanonymizer([("SRV-1042", "10.10.14.22")])
        out = sd.feed("host SRV-1042 open") + sd.flush()
        assert out == "host 10.10.14.22 open"

    def test_no_mappings_passes_text_through(self):
        sd = StreamingDeanonymizer([])
        out = sd.feed("nothing to change here") + sd.flush()
        assert out == "nothing to change here"


class TestBoundaryStraddle:
    def test_surrogate_split_across_two_deltas_is_deanonymized(self):
        sd = StreamingDeanonymizer([("SRV-1042", "10.10.14.22")])
        out = sd.feed("host SRV-10") + sd.feed("42 open") + sd.flush()
        assert out == "host 10.10.14.22 open"
        assert "SRV-1042" not in out

    def test_partial_surrogate_is_never_emitted_early(self):
        # After the first delta, only "SRV-10" has arrived — the de-anonymizer
        # must hold it back, never emitting the partial token.
        sd = StreamingDeanonymizer([("SRV-1042", "10.10.14.22")])
        first = sd.feed("host SRV-10")
        assert "SRV" not in first

    def test_surrogate_split_char_by_char(self):
        sd = StreamingDeanonymizer([("SRV-1042", "10.10.14.22")])
        out = "".join(sd.feed(c) for c in "x SRV-1042 y") + sd.flush()
        assert out == "x 10.10.14.22 y"


class TestOrdering:
    def test_longest_surrogate_wins_over_substring(self):
        # "SRV-1042" must be resolved as a whole, not have "SRV" replaced inside it.
        mappings = [("SRV-1042", "fileserver.corp.local"), ("SRV", "boxname")]
        sd = StreamingDeanonymizer(mappings)
        out = sd.feed("SRV-1042 and SRV alone") + sd.flush()
        assert out == "fileserver.corp.local and boxname alone"


class TestEquivalenceWithBatch:
    MAPPINGS = [
        ("SRV-DATACENTER-01", "fileserver.internal.corp"),  # long surrogate
        ("SRV-1042", "10.10.14.22"),
        ("USR-77", "j.martins"),
        ("SRV", "genericbox"),
    ]
    TEXT = (
        "Recon: SRV-1042 hosts the app; SRV-DATACENTER-01 is the file server. "
        "User USR-77 has admin on SRV. Pivot from SRV-1042 to USR-77's box."
    )

    @pytest.mark.parametrize("chunk_size", [1, 2, 3, 5, 7, 13, 32, 1000])
    def test_any_chunking_equals_batch_deanonymize(self, chunk_size):
        sd = StreamingDeanonymizer(self.MAPPINGS)
        pieces = [
            self.TEXT[i : i + chunk_size]
            for i in range(0, len(self.TEXT), chunk_size)
        ]
        streamed = "".join(sd.feed(p) for p in pieces) + sd.flush()
        assert streamed == _batch_replace(self.MAPPINGS, self.TEXT)

    def test_no_surrogate_survives_in_streamed_output(self):
        sd = StreamingDeanonymizer(self.MAPPINGS)
        streamed = "".join(sd.feed(c) for c in self.TEXT) + sd.flush()
        for surrogate, _ in self.MAPPINGS:
            assert surrogate not in streamed
