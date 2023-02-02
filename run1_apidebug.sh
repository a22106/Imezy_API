#!/bin/sh
python modules/duplicate.py -d1 ../stable-diffusion-webui-test/generated -d2 ../stable-diffusion-webui/generated # 생성 이미지 복사
python modules/duplicate.py -d1 ../stable-diffusion-webui-test/logs -d2 ../stable-diffusion-webui/logs # 로그 복사
python modules/duplicate.py -c -d1 ../stable-diffusion-webui-test/modules/api/conf -d2 ../stable-diffusion-webui/modules/api/conf # 설정 복사
python modules/duplicate.py -d1 ../stable-diffusion-webui-test/models -d2 ../stable-diffusion-webui/models # 모델 복사
python modules/duplicate.py -d1 ../stable-diffusion-webui-test/test -d2 ../stable-diffusion-webui/test # 테스트 파일 복사
python3 webui.py --listen --cors-allow-origins "*" --api --ui-debug-mode
