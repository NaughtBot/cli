#!/bin/sh
# Post-install script for oobsign

# Update shared library cache
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi

exit 0
