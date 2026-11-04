"""Pack-In integration constants."""

from homeassistant.const import Platform

DOMAIN = "packin"
VERSION = "0.1.1"
PLATFORMS = [Platform.TODO, Platform.CALENDAR, Platform.DEVICE_TRACKER, Platform.SENSOR, Platform.BUTTON]
LOCATION_INTERVALS = [0, 5, 10, 15, 30, 60]
CONF_LOCATION_INTERVAL = "location_interval"
DEFAULT_LOCATION_INTERVAL = 10
