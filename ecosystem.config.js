module.exports = {
  apps: [
    // API 服务器
    {
      name: 'free-proxy-api',
      script: './free-proxy-hunter-api-server',
      cwd: '/Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-hunter-api-server',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      restart_delay: 5000,
      max_restarts: 10,
      min_uptime: '10s',
      max_memory_restart: '512M',
      log_file: './logs/api-combined.log',
      out_file: './logs/api-out.log',
      error_file: './logs/api-error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      env: {
        GO_ENV: 'production',
        PORT: '53361'
      },
      watch: false,
      kill_timeout: 5000,
      listen_timeout: 10000
    },

    // 前端开发服务器
    {
      name: 'free-proxy-web',
      script: 'npm',
      args: 'run dev',
      cwd: '/Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-hunter-webpage',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      restart_delay: 3000,
      max_restarts: 5,
      min_uptime: '10s',
      max_memory_restart: '512M',
      log_file: './logs/web-combined.log',
      out_file: './logs/web-out.log',
      error_file: './logs/web-error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      env: {
        NODE_ENV: 'development'
      },
      watch: false,
      kill_timeout: 5000
    },

    // 代理扫描器
    {
      name: 'free-proxy-scanner',
      script: './scanner',
      cwd: '/Users/cc11001100/github/free-proxy-hunter/free-proxy-hunter/free-proxy-scanner',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      restart_delay: 10000,
      max_restarts: 5,
      min_uptime: '30s',
      max_memory_restart: '1G',
      log_file: './logs/scanner-combined.log',
      out_file: './logs/scanner-out.log',
      error_file: './logs/scanner-error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      env: {
        GO_ENV: 'production'
      },
      watch: false,
      kill_timeout: 10000,
      listen_timeout: 15000
    }
  ]
};
