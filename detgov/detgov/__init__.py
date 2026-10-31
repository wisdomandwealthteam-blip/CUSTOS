"""DetGov: deterministic governance gate (userspace Python package, standard library only)."""
from .core.firewall import Firewall
from .core.router import DetGovRouter, GovernanceViolation

__version__ = "1.0.0"
__all__ = ["Firewall", "DetGovRouter", "GovernanceViolation", "__version__"]
