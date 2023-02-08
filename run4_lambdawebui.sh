#!/bin/sh
python modules/duplicate.py -d1 ./generated -d2 ../stable-diffusion-webui/generated
python modules/duplicate.py -d1 ./logs -d2 ../stable-diffusion-webui/logs
python modules/duplicate.py -c -d1 ./modules/api/conf -d2 ../stable-diffusion-webui/modules/api/conf 
pm2 start webui.py --name="webui" -f --interpreter python -- --listen --cors-allow-origins "*" --api --enable-insecure-extension-access