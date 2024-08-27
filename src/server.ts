import express, { NextFunction, Request, Response } from 'express';
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
import { File } from './database/file';
import { Utilities } from './utilities';
import { StatsStorage } from './statistics/cluster-stats';
import { HourlyStatsStorage } from './statistics/hourly-stats';
import cookieParser from 'cookie-parser';

// 创建一个中间件函数
const logMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // 调用下一个中间件
    next();

    // 在响应完成后记录访问日志
    res.on('finish', () => {
        logAccess(req, res);
    });
};

const logAccess = (req: Request, res: Response) => {
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.headers['x-real-ip'] || req.ip;
    console.log(`${req.method} ${req.originalUrl} ${req.protocol} <${res.statusCode}> - [${ip}] ${userAgent}`);
};

// 使用对象解构来移除敏感信息
const removeSensitiveInfo = ({ clusterSecret, ...rest }: ClusterEntity) => rest;

export class Server {
    private app;
    private io: SocketIOServer;
    private httpsServer: https.Server;
    protected db: SQLiteHelper;
    protected files: File[];
    protected isUpdating: boolean = false;
    protected clusters: ClusterEntity[];
    protected avroBytes: Uint8Array;
    protected sessionToClusterMap: Map<string, ClusterEntity> = new Map();
    protected stats: StatsStorage[];
    protected centerStats: HourlyStatsStorage;

    public constructor() {
        this.files = [];
        this.avroBytes = new Uint8Array();

        // 创建 Express 应用
        this.app = http2Express(express);

        // 创建文件夹
        if (!fs.existsSync('./data')) fs.mkdirSync('./data');
        if (!fs.existsSync('./files')) fs.mkdirSync('./files');
        this.db = new SQLiteHelper("./data/database.sqlite");

        this.db.createTable<UserEntity>(UserEntity);
        this.db.createTable<ClusterEntity>(ClusterEntity);
        this.stats = this.db.getEntities<ClusterEntity>(ClusterEntity).map(c => new StatsStorage(c.clusterId));
        this.centerStats = new HourlyStatsStorage();

        this.clusters = this.db.getEntities<ClusterEntity>(ClusterEntity);

        // 读取证书和私钥文件
        const keyPath = path.resolve(Config.getInstance().certificateDir, 'key.pem');
        const certPath = path.resolve(Config.getInstance().certificateDir, 'cert.pem');
        const privateKey = fs.readFileSync(keyPath, 'utf8');
        const certificate = fs.readFileSync(certPath, 'utf8');
        const credentials = { key: privateKey, cert: certificate };

        // 通过访问唯一 instance 来触发单例模式的创建
        JwtHelper.getInstance();

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

    public init(): void {
        this.updateFiles();
        this.setupRoutes();
    }

    public async updateFiles(): Promise<void> {
        this.isUpdating = true;
        console.log('Updating files...');
        try {
            await Utilities.updateGitRepositories("./files");
            const files = Utilities.scanFiles("./files");
            const fileTasks = files.map(async file => {
                const f = await File.createInstanceFromPath(`.${file}`);
                f.path = f.path.substring(1);
                return f;
            });
            this.files = await Promise.all(fileTasks);
            this.avroBytes = await Utilities.getAvroBytes(this.files);
            console.log(`...file list was successfully updated. Found ${this.files.length} files`);
            return;
        }
        catch (error) {
            throw error;
        }
        finally {
            this.isUpdating = false;
        }
    }

    public start(): void {
        // 启动 HTTPS 服务器
        this.httpsServer.listen(Config.getInstance().port, () => {
          console.log(`HTTPS Server running on https://localhost:${Config.getInstance().port}`);
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
        // 设置中间件
        this.app.use(logMiddleware);
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(cookieParser());

        // 设置路由
        this.app.get('/93AtHome/list_clusters', (req, res) => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(this.db.getEntities<ClusterEntity>(ClusterEntity)));
        });
        this.app.get('/93AtHome/list_files', (req, res) => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(this.files));
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
                            'User-Agent': 'Open93AtHome-V3/3.0.0' // GitHub API要求设置User-Agent
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
        this.app.get('/93AtHome/update_files', async (req: Request, res: Response) => {
            const token = req.query.token as string || '';
            if (token !== Config.getInstance().adminToken) {
                return res.status(403).send(); // 禁止访问
            }
            if (this.isUpdating) {
                return res.status(409).send('Update in progress');
            }

            this.updateFiles();
            return res.status(204).send();
        });
        this.app.get('/openbmclapi-agent/challenge', (req: Request, res: Response) => {
            res.setHeader('Content-Type', 'application/json');
        
            const clusterId = req.query.clusterId as string || '';
        
            if (this.clusters.some(c => c.clusterId === clusterId)) {
                const cluster = this.clusters.find(c => c.clusterId === clusterId);
                if (!cluster) {
                    res.status(404).send();
                    return;
                }
                if (cluster.isBanned) {
                    res.status(403).send();
                    return;
                }
                const token = JwtHelper.getInstance().issueToken({
                    clusterId: clusterId
                }, "cluster-challenge", 60 * 5);
        
                res.status(200).json({ challenge: token });
            } else {
                res.status(404).send();
            }
        });
        // 处理 POST 请求
        this.app.post('/openbmclapi-agent/token', (req: Request, res: Response) => {
            res.setHeader('Content-Type', 'application/json');
        
            // 从请求体中获取参数
            const clusterId = req.body.clusterId as string;
            const signature = req.body.signature as string;
            const challenge = req.body.challenge as string;
            const claims = JwtHelper.getInstance().verifyToken(challenge, 'cluster-challenge') as { clusterId: string };
            const cluster = this.clusters.find(c => c.clusterId === claims.clusterId);
        
            if (cluster) {

                if (claims && claims.clusterId === clusterId && Utilities.computeSignature(challenge, signature, cluster.clusterSecret)) {
                    const token = JwtHelper.getInstance().issueToken(
                        { clusterId: clusterId },
                        'cluster',
                        60 * 60 * 24 // 过期时间：24小时
                    );
                
                    res.status(200).json({
                        token,
                        ttl: 1000 * 60 * 60 * 24 // TTL：24小时
                    });
                } else {
                    res.status(403).send(); // 禁止访问
                }
            } else {
                res.status(404).send(); // 未找到
            }
        });
        this.app.get('/openbmclapi/files', (req: Request, res: Response) => {
            if (!Utilities.verifyClusterRequest(req)) {
                res.status(403).send(); // 禁止访问
                return;
            }
            res.setHeader('Content-Disposition', 'attachment; filename="files.avro"');
            
            let lastModified = Number(req.query.lastModified);
            lastModified = Number.isNaN(lastModified)? 0 : lastModified;

            if (lastModified === 0) {
                res.status(200).send(this.avroBytes);
            }
            else {
                const files = this.files.filter(f => f.lastModified > lastModified);
                if (files.length === 0){
                    res.status(204).send();
                    return;
                }
                res.send(Utilities.getAvroBytes(files));
            }
        });
        this.app.get('/openbmclapi/configuration', (req: Request, res: Response) => {
            if (!Utilities.verifyClusterRequest(req)) {
                res.status(403).send(); // 禁止访问
                return;
            }
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json({ sync: { concurrency: 10, source: "center" }});
        });
        this.app.get('/openbmclapi/download/:hash([0-9a-f]{32})', (req: Request, res: Response) => {
            if (!Utilities.verifyClusterRequest(req)) {
                res.status(403).send(); // 禁止访问
                return;
            }
            const hash = req.params.hash;
            const file = this.files.find(f => f.hash === hash);
            if (file) {
                res.sendFile(path.join(__dirname, file.path.substring(1)));
            } else {
                res.status(404).send();
            }
        });
        this.app.get('/files/*', (req: Request, res: Response) => {
            const p = decodeURI(req.path);
            const file = this.files.find(f => f.path === p);
            if (file) {
                let cluster = Utilities.getRandomElement(this.clusters.filter(c => c.isOnline));
                this.centerStats.addData({ hits: 1, bytes: file.size });
                if (!cluster) {
                    res.sendFile(file.path.substring(1), {
                        root: ".",
                        maxAge: "30d"
                    });
                    return;
                }

                res.status(302)
                .setHeader('Location', `http://${cluster.endpoint}:${cluster.port}/download/${file.hash}?${Utilities.getSign(file.hash, cluster.clusterSecret)}`)
                .send();
                cluster.pendingHits++;
                cluster.pendingTraffic += file.size;
            } else {
                res.status(404).send();
            }
        });
        this.app.get('/93AtHome/centerStatistics', (req: Request, res: Response) => {
            res.setHeader('Content-Type', 'application/json');
            const data = this.centerStats.getLast30DaysHourlyStats();
            res.status(200).json({
                dailyHits: data.map(d => {
                    let hits = 0;
                    d.filter(h => h !== null).forEach(h => hits += h.hits);
                    return hits;
                }),
                dailyBytes: data.map(d => {
                    let bytes = 0;
                    d.filter(b => b !== null).forEach(b => bytes += b.bytes);
                    return bytes;
                })
            });
        });
        this.app.get('/93AtHome/clusterStatistics', (req: Request, res: Response) => {
            res.setHeader('Content-Type', 'application/json');
            const clusterId = req.query.clusterId as string;
            const cluster = this.clusters.find(c => c.clusterId === clusterId);
            if (cluster) {
                const stats = this.stats.find(s => s.id === clusterId);
                if (stats) {
                    res.status(200).json(stats.getLast30DaysStats());
                } else {
                    res.status(404).send(); // 未找到统计数据
                }
            } else {
                res.status(404).send(); // 未找到集群
            }
        });
        this.app.get('/93AtHome/rank', async (req: Request, res: Response) => {
            // 先把节点按照在线和离线分成两部分，然后各自按照 traffic 从大到小排序，最后返回 JSON 字符串
            const onlineClusters = this.clusters.filter(c => c.isOnline);
            const offlineClusters = this.clusters.filter(c => !c.isOnline);
        
            const onlineClustersSorted = onlineClusters
                .sort((a, b) => b.traffic - a.traffic)
                .map(removeSensitiveInfo);
        
            const offlineClustersSorted = offlineClusters
                .sort((a, b) => b.traffic - a.traffic)
                .map(removeSensitiveInfo);
        
            // 添加 ownerName 并返回 JSON 响应
            const result = [
                ...onlineClustersSorted,
                ...offlineClustersSorted
            ].map(c => ({
                ...c,
                ownerName: this.db.getEntity<UserEntity>(UserEntity, c.owner)?.username || ''
            }));
        
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json(result);
        });
        
        this.app.get('/93AtHome/dashboard/user/profile', (req: Request, res: Response) => {
            const token = req.cookies.token;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.getInstance().verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send(); // 用户不存在
                return;
            }
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json({
                id: user.id,
                login: user.username,
                avatar_url: user.photo
            });
        });
        this.app.post('/93AtHome/dashboard/user/bindCluster', (req: Request, res: Response) => {
            const token = req.cookies.token;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.getInstance().verifyToken(token, 'user') as { userId: number, exp: number }).userId);
            if (!user) {
                res.status(404).send(); // 用户不存在
                return;
            }
            const body = req.body as { clusterId: string, clusterSecret: string };
            res.setHeader('Content-Type', 'application/json');
            const matches = this.clusters.filter(c => c.clusterId === body.clusterId && c.clusterSecret === body.clusterSecret && Number(c.owner) === 0);
            if (matches.length === 0) {
                res.status(404).send(); // 集群不存在
                return;
            }
            matches.forEach(c => {
                c.owner = user.id;
                this.db.update(c);
            });
            res.status(200).json(matches.map(c => removeSensitiveInfo(c)));
        });
        this.app.post('/93AtHome/dashboard/user/unbindCluster', (req: Request, res: Response) => {
            const token = req.cookies.token;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.getInstance().verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send(); // 用户不存在
                return;
            }
            const body = req.body as { clusterId: string };
            res.setHeader('Content-Type', 'application/json');
            const matches = this.clusters.filter(c => c.clusterId === body.clusterId && Number(c.owner) === user.id);
            if (matches.length === 0) {
                res.status(404).send(); // 集群不存在
                return;
            }
            matches.forEach(c => {
                c.owner = 0;
                this.db.update(c);
            });
            res.status(200).json(matches.map(c => removeSensitiveInfo(c)));
        });
        this.app.get('/93AtHome/dashboard/user/clusters', (req: Request, res: Response) => {
            const token = req.cookies.token;
            const clusterId = req.query.clusterId as string;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.getInstance().verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send(); // 用户不存在
                return;
            }
            res.setHeader('Content-Type', 'application/json');
            if (!clusterId) {
                const clusters = this.clusters.filter(c => c.owner === user.id);
                res.status(200).json(clusters.map(c => removeSensitiveInfo(c)));
            } else {
                const cluster = this.clusters.find(c => c.clusterId === clusterId && c.owner === user.id);
                if (!cluster) {
                    res.status(404).send(); // 集群不存在
                    return;
                }
                res.status(200).json(removeSensitiveInfo(cluster));
            }
        });
        this.app.post('/93AtHome/dashboard/user/cluster/profile', (req: Request, res: Response) => {
            const token = req.cookies.token;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.getInstance().verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send(); // 用户不存在
                return;
            }
            const clusterId = req.query.clusterId as string;
            const cluster = this.clusters.find(c => c.clusterId === clusterId && c.owner === user.id);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            res.setHeader('Content-Type', 'application/json');
            const clusterName = req.body.clusterName as string || null;
            const bandwidth = req.body.bandwidth as number || null;
            const sponsor = req.body.sponsor as string || null;
            const sponsorUrl = req.body.sponsorUrl as string || null;

            // 将以上四个可选项目更新到集群，如果为null说明不进行更改
            if (clusterName) {
                cluster.clusterName = clusterName;
            }

            if (bandwidth) {
                cluster.bandwidth = bandwidth;
            }

            if (sponsor) {
                cluster.sponsor = sponsor;
            }

            if (sponsorUrl) {
                cluster.sponsorUrl = sponsorUrl;
            }

            this.db.update(cluster);
            res.status(200).json(removeSensitiveInfo(cluster));
        });
        
        this.app.get('/93AtHome/dashboard/user/cluster/reset_secret', (req: Request, res: Response) => {
            const token = req.cookies.token;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.getInstance().verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send(); // 用户不存在
                return;
            }
            res.setHeader('Content-Type', 'application/json');
            const cluster = this.clusters.find(c => c.clusterId === req.query.clusterId && c.owner === user.id);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            const secret = Utilities.generateRandomString(32);
            cluster.clusterSecret = secret;
            this.db.update(cluster);
            res.status(200).json({
                clusterSecret: secret
            });
        });
        this.app.post('/93AtHome/random', (req: Request, res: Response) => {
            res.status(302);
            res.setHeader('Location', Utilities.getRandomElement(this.files)?.path || '');
            res.send();
        });
    }

    public setupSocketIO(): void {
        this.io.use((socket, next) => {
            try {
                const token = socket.handshake.auth?.token;
                if (!token) {
                    throw new Error('No token provided');
                }
        
                // 验证 token
                const object = JwtHelper.getInstance().verifyToken(token, 'cluster');
        
                // 检查 payload 是否是对象类型，并且包含 exp 字段
                if (object && typeof object === 'object' && 'exp' in object && 'clusterId' in object) {
                    const payload = object as { exp: number, clusterId: string };
                    const exp = payload.exp;
                    const cluster = this.clusters.find(c => c.clusterId === payload.clusterId);
                    if (!cluster) {
                        throw new Error('Cluster not found');
                    }
                    if (exp > Date.now() / 1000) {
                        this.sessionToClusterMap.set(socket.id, cluster);
                        console.log(`SOCKET ${socket.handshake.url} socket.io <ACCEPTED> - [${socket.handshake.headers["x-real-ip"] || socket.handshake.address}] ${socket.handshake.headers['user-agent']}`);
                        return next(); // 验证通过，允许连接
                    } else {
                        throw new Error('Token expired');
                    }
                } else {
                    throw new Error('Token payload invalid');
                }
            } catch (err) {
                console.error('Authentication error');
                socket.disconnect(true);
                return next(new Error('Authentication error')); // 验证失败，拒绝连接
            }
        });
        

        // 监听 Socket.IO 连接事件
        this.io.on('connection', (socket) => {
            console.log(`SOCKET ${socket.handshake.url} socket.io <CONNECTED> - [${socket.handshake.headers["x-real-ip"] || socket.handshake.address}] ${socket.handshake.headers['user-agent']}`);

            socket.on('enable', (data, ack: Function) => {
                const enableData = data as  {
                    host: string,
                    port: number,
                    version: string,
                    byoc: boolean,
                    noFastEnable: boolean,
                    flavor: {
                        runtime: string,
                        storage: string
                    }
                };

                const randomFileCount = 5;
                const randomFiles = Utilities.getRandomElements(this.files, randomFileCount);
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster) {
                    ack({ message: "Cluster not found"});
                    return;
                }

                const urls = randomFiles.map(f => `http://${enableData.host}:${enableData.port}/download/${f.hash}?${Utilities.getSign(f.hash, cluster.clusterSecret)}`);

                Utilities.checkUrls(urls)
                .then(hashes => {
                    const realHashes = randomFiles.map(f => f.hash);
                    if (hashes.every((hash, index) => hash.hash === realHashes[index])) {
                        cluster.endpoint = enableData.host;
                        cluster.port = enableData.port;
                        cluster.isOnline = true;
                        ack([null, true]);
                    }
                    else {
                        const differences = [
                            ...realHashes.filter(hash => !hashes.map(h => h.hash).includes(hash)), // 存在于 objectHashes 中但不存在于 hashArray 中
                            ...hashes.filter(hash => !realHashes.includes(hash.hash))   // 存在于 hashArray 中但不存在于 objectHashes 中
                        ];
                        ack({ message: `Hash mismatch: ${differences.join(', ')}` });
                    }
                })
            });

            socket.on('keep-alive', (data, ack: Function) => {
                const keepAliveData = data as  {
                    time: string,
                    hits: number,
                    bytes: number
                };

                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster || !cluster.isOnline) {
                    ack([null, false]);
                }
                else {
                    console.log(`SOCKET ${socket.handshake.url} socket.io <KEEP-ALIVE> - [${socket.handshake.headers["x-real-ip"] || socket.handshake.address}] ${socket.handshake.headers['user-agent']}`);
                    const hits = Math.min(keepAliveData.hits, cluster.pendingHits);
                    const traffic = Math.min(keepAliveData.bytes, cluster.pendingTraffic);
                    cluster.pendingHits += hits;
                    cluster.pendingTraffic += traffic;
                    cluster.pendingHits = 0;
                    cluster.pendingTraffic = 0;
                    cluster.traffic += traffic;
                    cluster.hits += hits;
                    ack([null, new Date(Date.now()).toISOString()]);
                    this.db.update(cluster);
                    this.stats.filter(c => c.id === cluster.clusterId).forEach(s => s.addData({ hits: hits, bytes: traffic }));
                }
            });

            socket.on('disable', (data, ack: Function) => {
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster || !cluster.isOnline) {
                    ack([null, false]);
                }
                else {
                    console.log(`SOCKET ${socket.handshake.url} socket.io <DISABLE> - [${socket.handshake.headers["x-real-ip"] || socket.handshake.address}] ${socket.handshake.headers['user-agent']}`);
                    cluster.isOnline = false;
                    socket.send('Bye. Have a good day!');
                    ack([null, true]);
                    this.db.update(cluster);
                }
            });

            socket.on('disconnect', () => {
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (cluster) {
                    console.log(`SOCKET ${socket.handshake.url} socket.io <DISCONNECTED> - [${socket.handshake.headers["x-real-ip"] || socket.handshake.address}] ${socket.handshake.headers['user-agent']}`);
                    cluster.isOnline = false;
                }
            })
        });
    }
}