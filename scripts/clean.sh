#!/bin/bash

rm src/monocypher/*.so
pip freeze --exclude-editable \
    | cut -d'=' -f1 \
    | xargs pip uninstall -y
exit 0
