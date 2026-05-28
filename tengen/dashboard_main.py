"""Entry point: start the Tengen observability dashboard."""
from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    import uvicorn
    from tengen.config import settings
    from tengen.dashboard.app import app

    logger.info(
        "Tengen dashboard starting on http://%s:%d",
        settings.dashboard_host,
        settings.dashboard_port,
    )
    uvicorn.run(app, host=settings.dashboard_host, port=settings.dashboard_port, log_level="info")


if __name__ == "__main__":
    main()
