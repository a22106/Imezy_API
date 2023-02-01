#!/bin/sh
python modules/duplicate.py -d1 ../stable-diffusion-webui-test/generated -d2 ../stable-diffusion-webui/generated
python modules/duplicate.py -d1 ../stable-diffusion-webui-test/logs -d2 ../stable-diffusion-webui/logs
python modules/duplicate.py -c -d1 ../stable-diffusion-webui-test/modules/api/conf -d2 ../stable-diffusion-webui/modules/api/conf 
python webui.py --listen --cors-allow-origins "*" --api --ui-debug-mode
