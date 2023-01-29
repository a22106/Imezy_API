python modules/duplicate.py -d1 /data/StableDiffusion/stable-diffusion-webui-test/generated -d2 /data/StableDiffusion/stable-diffusion-webui-pius/generated
python modules/duplicate.py -d1 /data/StableDiffusion/stable-diffusion-webui-test/logs -d2 /data/StableDiffusion/stable-diffusion-webui-pius/logs
python modules/duplicate.py -c -d1 /data/StableDiffusion/stable-diffusion-webui-test/modules/api/conf -d2 /data/StableDiffusion/stable-diffusion-webui-pius/modules/api/conf 
python webui.py --listen --cors-allow-origins "*" --api --ui-debug-mode
