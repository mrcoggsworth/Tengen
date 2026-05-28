"""Entry point: start the RabbitMQ-backed routing pipeline."""
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
    from tengen.routing import routes  # noqa: F401 — registers all routes on import
    from tengen.routing.router import Router
    from tengen.queue.queues import QUEUE_ALERTS
    from tengen.config import settings

    router = Router(rabbitmq_url=settings.rabbitmq_url, source_queue=QUEUE_ALERTS)
    logger.info("Tengen router starting on queue '%s'", QUEUE_ALERTS)
    try:
        router.run()
    except KeyboardInterrupt:
        logger.info("Router stopped.")


if __name__ == "__main__":
    main()
