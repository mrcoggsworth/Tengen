"""Entry point: start the enriched-alert and DLQ forwarder workers."""
from __future__ import annotations

import logging
import sys
import threading

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    from tengen.config import settings
    from tengen.forwarder.enriched_forwarder import EnrichedAlertForwarder
    from tengen.forwarder.dlq_forwarder import DLQForwarder

    enriched_fwd = EnrichedAlertForwarder(
        rabbitmq_url=settings.rabbitmq_url,
        splunk_hec_url=settings.splunk_hec_url,
        splunk_hec_token=settings.splunk_hec_token,
        splunk_index=settings.splunk_index,
        batch_size=settings.splunk_batch_size,
    )
    dlq_fwd = DLQForwarder(
        rabbitmq_url=settings.rabbitmq_url,
        splunk_hec_url=settings.splunk_hec_url,
        splunk_hec_token=settings.splunk_hec_token,
        splunk_index=f"{settings.splunk_index}-dlq",
        batch_size=settings.splunk_batch_size,
    )

    t1 = threading.Thread(target=enriched_fwd.run, name="enriched-forwarder", daemon=True)
    t2 = threading.Thread(target=dlq_fwd.run, name="dlq-forwarder", daemon=True)
    t1.start()
    t2.start()
    logger.info("Tengen forwarders started (enriched + DLQ).")
    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        logger.info("Forwarders stopped.")


if __name__ == "__main__":
    main()
