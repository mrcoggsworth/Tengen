"""Import all route modules to trigger auto-registration with the RouteRegistry."""
from tengen.routing.routes.cloud.aws import cloudtrail, eks, guardduty  # noqa: F401
from tengen.routing.routes.cloud.gcp import event_audit  # noqa: F401
from tengen.routing.routes.cloud.azure import activity  # noqa: F401
from tengen.routing.routes.edr import crowdstrike  # noqa: F401
from tengen.routing.routes.k8s import audit  # noqa: F401
from tengen.routing.routes.network import firewall  # noqa: F401
