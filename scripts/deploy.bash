#!/bin/bash

./scripts/compile.bash
gsutil setwebcfg -m index.html gs://www.bit2factor.org
gsutil -h "Cache-Control:public,max-age=86400" cp -z 'html,js,css,txt' -a public-read -R build/index.html gs://www.bit2factor.org
