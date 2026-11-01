"""A separate namespace runs pure model tests without simulating HA itself."""

from pathlib import Path
import sys
from types import ModuleType

package = ModuleType("packin_pure")
package.__path__ = [str(Path(__file__).parents[1] / "custom_components/packin")]
sys.modules["packin_pure"] = package
