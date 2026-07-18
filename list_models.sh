#!/usr/bin/env bash
set -euo pipefail
cd /home/wjt/CardDiffBench_official_a2a_main_20260712
set -a
. ./.env
set +a
.venv/bin/python - <<'PY'
import json, os, requests
for url in (os.environ['SUT_API_BASE'].rstrip('/') + '/v1/models', os.environ['SUT_API_BASE'].rstrip('/') + '/models'):
    try:
        r=requests.get(url,headers={'Authorization':'Bearer '+os.environ['SUT_API_KEY']},timeout=30)
        print(url,r.status_code,r.headers.get('content-type'))
        if 'json' in r.headers.get('content-type',''):
            d=r.json()
            print('\n'.join(sorted(str(x.get('id')) for x in d.get('data',[]) if isinstance(x,dict))))
    except Exception as e: print(type(e).__name__,str(e))
PY
