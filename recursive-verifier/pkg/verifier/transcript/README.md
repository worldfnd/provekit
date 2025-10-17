# pkg/verifier/transcript

Parsers for Nimue transcripts live in this package. They extract verifier hints
from the raw byte streams and return strongly typed structures that can be fed
into higher-level orchestration code without touching the legacy parsing logic.
