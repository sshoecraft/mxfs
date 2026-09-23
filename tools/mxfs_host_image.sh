#!/bin/bash
# tools/mxfs_host_image.sh [node] — the host-side image that backs the rig's
# LUN, or nothing.
#
# Prints the path alone on stdout and exits 0, or prints the ABORT text and
# exits 2.  It is tests/lib/rig.sh mxfs_host_image for a harness that does
# not source the library: the image must be DECLARED for the rig
# (data/rigs.json[<tag>].host_image, or MXFS_HOST_IMAGE_PATH for one run) and
# its envelope fsid, read direct from the file, must equal the LUN's — the
# named node's resolved device, else the fsid the cluster marker recorded at
# prep.  A rig whose LUN no file on this host backs (the qnap) declares none,
# and the caller ABORTs instead of reading some other filesystem's platter
# and printing a verdict about MXFS from it.
#
# Usage:  IMG=$(tools/mxfs_host_image.sh [node]) || { echo "$IMG"; exit 2; }
set -u
cd "$(dirname "$0")/.." || exit 2
LABEL=${LABEL:-host-image}
OUT=${OUT:-/tmp}
. tests/lib/rig.sh
line=$(mxfs_host_image "${1:-}")
rc=$?
if [ "$rc" != 0 ]; then echo "$line"; exit 2; fi
echo "$line" >&2
echo "$line" | grep -ao '^HOST-IMAGE path=[^ ]*' | cut -d= -f2-
