"""Backwards-compatibility re-exports. The CLI has moved to proxy.cli."""

from ..cli import (  # noqa: F401
    analyze_connections,
    connection_key,
    find_policies_in_workflow,
    format_connection,
    load_connections_log,
    main,
)
from .parser import validate_policy  # noqa: F401
