
module.exports = {
  apps: [{
    name: 'timetracker',
    script: './dist/index.js',
    instances: 1, // Start with 1 instance for easier debugging
    exec_mode: 'fork', // Use fork mode instead of cluster for Windows
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      TZ: 'America/Los_Angeles'
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    max_memory_restart: '1G',
    restart_delay: 4000,
    max_restarts: 3,
    min_uptime: '10s',
    kill_timeout: 5000,
    listen_timeout: 8000,
    wait_ready: true,
    autorestart: true,
    watch: false,
    ignore_watch: ['node_modules', 'logs'],
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true
  }]
};
