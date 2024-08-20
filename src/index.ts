import { Server } from "./server";

// 创建 Server 实例
const server = new Server();
server.setupRoutes();
server.start();