module.exports = {
  apps: [
    {
      name: 'imezy_api',
      script: 'webui.py',
      interpreter: 'python',
      args: '--listen --cors-allow-origins "*" --api --enable-insecure-extension-access',
      instances: 1,
      autorestart: true,
      watch: false,
      env: {
        DEVICE_ID: 3
      }
    }
  ]
  // deploy: {
  //   production: {
  //     user: 'deploy',
  //     host: 'example.com',
  //     ref: 'origin/master',
  //     repo: 'git@github.com:yourusername/yourrepository.git',
  //     path: '/var/www/production',
  //     'post-deploy': 'pip install -r requirements.txt && pm2 startOrRestart ecosystem.config.js --env production'
  //   }
  // }
};
