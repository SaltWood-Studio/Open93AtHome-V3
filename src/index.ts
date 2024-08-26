import { exec } from "child_process";
import { Config } from "./config";
import { Server } from "./server";
import { Utilities } from "./utilities";

Config.init();

if (Utilities.isRunningInDocker()) {
    console.debug("Running in Docker container");
    exec('git config --global --add safe.directory "*"');
} else {
    console.debug("Not running in Docker container");
}

// 创建 Server 实例
const server = new Server();
server.init();
server.start();