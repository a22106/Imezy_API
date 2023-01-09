<<<<<<< HEAD
python modules/duplicate.py -d1 /data/StableDiffusion/stable-diffusion-webui-test/generated -d2 /data/StableDiffusion/stable-diffusion-webui-pius/generated
=======
python modules/duplicate.py
>>>>>>> master
python modules/duplicate.py -d1 /data/StableDiffusion/stable-diffusion-webui-test/logs -d2 /data/StableDiffusion/stable-diffusion-webui-pius/logs
python webui.py --listen --cors-allow-origins "*" --api --device-id 1 --enable-insecure-extension-access
