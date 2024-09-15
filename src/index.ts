import { exec } from "child_process";
import { Config } from './Config.js';
import { Server } from './Server.js';
import { Utilities } from './Utilities.js';

function onStop(signal: string) {
    server.db.close();
    server.stats.forEach(stats => stats.stopAutoSave());
    server.centerStats.stopAutoSave();
    console.log(`Received ${signal}. Shutting down...`);
    process.exit(0);
}

Config.init();

if (Utilities.isRunningInDocker()) {
    console.debug("Running in Docker container");
    exec('git config --global --add safe.directory "*"');
} else {
    console.debug("Not running in Docker container");
}

process.on("SIGINT", onStop);
process.on("SIGTERM", onStop);

// 创建 Server 实例
const server = new Server();
await server.init();
server.start();