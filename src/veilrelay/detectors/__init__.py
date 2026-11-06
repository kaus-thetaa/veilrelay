"""Built-in detection layers."""

from veilrelay.detectors.base import Detector
from veilrelay.detectors.regexes import BuiltinDetector
from veilrelay.detectors.secrets import SecretDetector

__all__ = ["BuiltinDetector", "Detector", "SecretDetector"]
