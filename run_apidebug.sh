python modules/duplicate.py
python modules/duplicate.py -d1 /data/StableDiffusion/stable-diffusion-webui-test/logs -d2 /data/StableDiffusion/stable-diffusion-webui-pius/logs
python webui.py --listen --cors-allow-origins "*" --api --device-id 1 --ui-debug-mode --port 7861
