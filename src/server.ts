import express, { Request, Response } from 'express';
import https from 'https';
import fs from 'fs';
import path from 'path';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import JwtHelper from './jwt-helper';
import axios from 'axios';
import { SQLiteHelper } from './sqlite';
import { UserEntity } from './database/user';
import { ClusterEntity } from './database/cluster';
import http2Express from 'http2-express-bridge';
import { Config } from './config';
import { GitHubUser } from './database/github-user';

export class Server {
    private app;
    private io: SocketIOServer;
    private httpsServer: https.Server;
    protected db: SQLiteHelper;

    public constructor() {
        // 创建 Express 应用
        this.app = http2Express(express);
        this.db = new SQLiteHelper("database.sqlite");

        this.db.createTable<UserEntity>(UserEntity);
        this.db.createTable<ClusterEntity>(ClusterEntity);

        // 读取证书和私钥文件
        const keyPath = path.resolve(__dirname, '../key.pem');
        const certPath = path.resolve(__dirname, '../cert.pem');
        const privateKey = fs.readFileSync(keyPath, 'utf8');
        const certificate = fs.readFileSync(certPath, 'utf8');
        const credentials = { key: privateKey, cert: certificate };

        // 创建 HTTPS 服务器
        this.httpsServer = https.createServer(credentials, this.app);

        // 创建 Socket.IO 服务器
        this.io = new SocketIOServer(this.httpsServer, {
            cors: {
                origin: '*',
                methods: ['GET', 'POST']
            }
        });
    }

    public start(): void {
        // 启动 HTTPS 服务器
        const PORT = 21474;
        this.httpsServer.listen(PORT, () => {
          console.log(`HTTPS Server running on https://localhost:${PORT}`);
        });
    
        // 启动 Socket.IO 服务器
        // const SOCKET_PORT = 9300;
        // this.io.listen(SOCKET_PORT);
        // console.log(`Socket.IO Server running on http://localhost:${SOCKET_PORT}`);
    }

    public setupRoutes(): void {
        this.setupHttps();
        this.setupSocketIO();
    }

    public setupHttps(): void {
        // 设置路由
        this.app.get('/93AtHome/list_clusters', (req, res) => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(this.db.getEntities<ClusterEntity>(ClusterEntity)));
        });
        this.app.get('/93AtHome/dashboard/oauth_id', (req, res) => {
            res.statusCode = 200;
            res.end(Config.getInstance().githubOAuthClientId);
        });
        this.app.get('/93AtHome/dashboard/user/oauth', async (req: Request, res: Response) => {
            res.set("Content-Type", "application/json");
        
            try {
                const code = req.query.code as string || '';
        
                // 请求GitHub获取access_token
                const tokenResponse = await axios.post(`https://${Config.getInstance().githubUrl}/login/oauth/access_token`, {
                    code,
                    client_id: Config.getInstance().githubOAuthClientId,
                    client_secret: Config.getInstance().githubOAuthClientSecret
                }, {
                    headers: {
                        'Accept': 'application/json'
                    }
                });
        
                const tokenData = tokenResponse.data as { access_token: string };
                const accessToken = tokenData.access_token;
        
                let userResponse;
                try {
                    userResponse = await axios.get(`https://${Config.getInstance().githubApiUrl}/user`, {
                        headers: {
                            'Authorization': `token ${accessToken}`,
                            'Accept': 'application/json',
                            'User-Agent': 'YourAppName' // GitHub API要求设置User-Agent
                        }
                    }).then(response => response.data) as { id: number, login: string, avatar_url: string };
                } catch (error) {
                    console.error('Error fetching GitHub user info:', error as Error);
                    throw error; // 或者返回一个默认的错误响应
                }
             
                const user = GitHubUser.create(
                    userResponse.id,
                    userResponse.login,
                    userResponse.avatar_url
                );
        
                // 处理数据库操作
                let dbUser = this.db.getEntity<UserEntity>(UserEntity, user.id);
                if (dbUser) {
                    this.db.update(user.toUserEntity());
                } else {
                    this.db.insert<UserEntity>(user.toUserEntity());
                }
        
                // 生成JWT并设置cookie
                const token = JwtHelper.getInstance().issueToken({
                    userId: user.id,
                    clientId: Config.getInstance().githubOAuthClientId
                }, "user", 60 * 60 * 24);
        
                res.cookie('token', token, {
                    expires: new Date(Date.now() + 86400000), // 24小时后过期
                    secure: true
                });
        
                res.status(200).json({
                    avatar_url: user.avatar_url,
                    username: user.login,
                    id: user.id
                });
            } catch (error) {
                const err = error as Error;
                res.status(500).json({
                    error: `${err.name}: ${err.message}`
                });
            }
        });
    }

    public setupSocketIO(): void {
        this.io.use((socket, next) => {
            try {
                const token = socket.handshake.auth?.token;
                if (!token) {
                    throw new Error('No token provided');
                }
                console.log('token: ', token);
        
                // 验证 token
                const payload = JwtHelper.getInstance().verifyToken(token);
        
                // 检查 payload 是否是对象类型，并且包含 exp 字段
                if (payload && typeof payload === 'object' && 'exp' in payload) {
                    const exp = (payload as { exp: number }).exp; // 类型断言，确保 exp 存在
                    if (exp > Date.now() / 1000) {
                        return next(); // 验证通过，允许连接
                    } else {
                        throw new Error('Token expired');
                    }
                } else {
                    throw new Error('Token payload invalid');
                }
            } catch (err) {
                console.error('Authentication error');
                return next(new Error('Authentication error')); // 验证失败，拒绝连接
            }
        });
        

        // 监听 Socket.IO 连接事件
        this.io.on('connection', (socket) => {
            console.log('a user connected');
            socket.on('disconnect', () => {
                console.log('user disconnected');
            });

            // 监听客户端消息
            socket.on('message', (message) => {
                console.log('message: ', message);
                socket.emit('message', 'hello');
            });
        });
    }
}