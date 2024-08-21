import { Config } from "./config";
import { Server } from "./server";

Config.init();

// 创建 Server 实例
const server = new Server();
server.init();
server.start();