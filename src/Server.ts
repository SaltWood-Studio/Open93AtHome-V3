import express, { NextFunction, Request, Response } from 'express';
import https from 'https';
import fs from 'fs';
import path from 'path';
import { Server as SocketIOServer } from 'socket.io';
// import cors from 'cors';
import JwtHelper from './JwtHelper.js';
import { SQLiteHelper } from './SQLiteHelper.js';
import { UserEntity } from './database/User.js';
import { ClusterEntity } from './database/Cluster.js';
import http2Express from 'http2-express-bridge';
import { Config } from './Config.js';
import { GitHubUser } from './database/GitHubUser.js';
import { File } from './database/File.js';
import { Utilities } from './Utilities.js';
import { StatsStorage } from './statistics/ClusterStats.js';
import { HourlyStatsStorage } from './statistics/HourlyStats.js';
import cookieParser from 'cookie-parser';
import { Plugin } from './plugin/Plugin.js';
import { PluginLoader } from './plugin/PluginLoader.js';
import got, {type Got} from 'got'

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

export class Server {
    private app;
    private io: SocketIOServer;
    private httpsServer: https.Server;
    public db: SQLiteHelper;
    protected files: File[];
    protected isUpdating: boolean = false;
    protected clusters: ClusterEntity[];
    protected avroBytes: Uint8Array;
    protected sessionToClusterMap: Map<string, ClusterEntity> = new Map();
    protected stats: StatsStorage[];
    protected centerStats: HourlyStatsStorage;
    protected plugins: Plugin[];
    protected pluginLoader: PluginLoader;
    protected got: Got;
    protected sources: { name: string, count: number, lastUpdated: Date, isFromPlugin: boolean }[] = [];

    public constructor() {
        this.plugins = [];
        this.pluginLoader = new PluginLoader();
        this.pluginLoader.loadPlugins(this)
        .then(plugins => {
            this.plugins = plugins;
            plugins.forEach(plugin => plugin.init());
        })
        .catch(error => console.error(error));

        this.got = got.extend({
            headers: {
                'User-Agent': `93AtHome-V3/${Config.version}`
            }
        });

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

    public async updateFiles(checkClusters: boolean = false): Promise<void> {
        this.isUpdating = true;
        console.log('Updating files...');
        try {
            await Utilities.updateGitRepositories("./files");
            const oldFiles = this.files;
            await Promise.all(this.plugins.map(p => p.updateFiles()));
            const files = Utilities.scanFiles("./files");
            const fileTasks = (files as { files: string[] }[]).map(f => f.files).flat().map(async file => {
                const f = await File.createInstanceFromPath(`.${file}`);
                return f;
            });
            const localFiles = await Promise.all(fileTasks);
            const pluginFiles = await Promise.all(this.plugins.map(async p => {
                const files = await p.getFiles();
                return {
                    name: p.getName(),
                    count: files.length,
                    lastUpdated: new Date(),
                    isFromPlugin: true,
                    files
                }
            }));
            this.sources = [
                ...files.map(f => ({ name: f.name, count: f.count, lastUpdated: f.lastUpdated, isFromPlugin: f.isFromPlugin })),
                ...pluginFiles.map(p => ({ name: p.name, count: p.count, lastUpdated: p.lastUpdated, isFromPlugin: p.isFromPlugin })),
            ];
            this.files = [
                ...localFiles,
                ...pluginFiles.map(p => p.files).flat()
            ];
            this.avroBytes = await Utilities.getAvroBytes(this.files);
            console.log(`...file list was successfully updated. Found ${this.files.length} files`);
            this.isUpdating = false;
            if (checkClusters) {
                for (const cluster of this.clusters.filter(c => c.isOnline)) {
                    const message = await Utilities.checkSpecfiedFiles(Utilities.findDifferences(oldFiles, this.files, true), cluster); // 只查找新增的文件，不然删文件会把全部节点踢了
                    if (message) {
                        cluster.downReason = message;
                        cluster.isOnline = false;
                        this.db.update(cluster);
                        console.log(`Cluster ${cluster.clusterId} is down because of ${message}`);
                    }
                }
            }
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
        this.app.get('/', (req: Request, res: Response) => res.status(302).header('Location', '/dashboard').send());
        this.app.get('/93AtHome/list_clusters', (req, res) => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(this.db.getEntities<ClusterEntity>(ClusterEntity).map(c => c.getJson(true, true))));
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
                const tokenData = await this.got.post(`https://${Config.getInstance().githubUrl}/login/oauth/access_token`, {
                    form: {
                        code,
                        client_id: Config.getInstance().githubOAuthClientId,
                        client_secret: Config.getInstance().githubOAuthClientSecret
                    },
                    headers: {
                        'Accept': 'application/json'
                    },
                    responseType: 'json'
                }).json<{ access_token: string }>();
        
                const accessToken = tokenData.access_token;
        
                let userResponse = await this.got.get(`https://${Config.getInstance().githubApiUrl}/user`, {
                    headers: {
                        'Authorization': `token ${accessToken}`,
                        'Accept': 'application/json',
                        'User-Agent': 'Open93AtHome-V3/3.0.0' // GitHub API要求设置User-Agent
                    }
                }).json<{ id: number, login: string, avatar_url: string, name: string }>();
             
                const user = GitHubUser.create(
                    userResponse.id,
                    userResponse.name || userResponse.login || '',
                    userResponse.avatar_url
                );
        
                // 处理数据库操作
                let dbUser = this.db.getEntity<UserEntity>(UserEntity, user.id);
                if (dbUser) {
                    this.db.update(user.toUserWithDbEntity(dbUser));
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
                });

                if (this.db.getEntity<UserEntity>(UserEntity, user.id)?.isSuperUser) {
                    const adminToken = JwtHelper.getInstance().issueToken({
                        userId: user.id,
                        clientId: Config.getInstance().githubOAuthClientId
                    }, "admin", 60 * 60 * 24);
                    res.cookie('adminToken', adminToken, {
                        expires: new Date(Date.now() + 86400000), // 24小时后过期
                    });
                }
        
                res.status(200).json({
                    avatar_url: user.avatar_url,
                    username: user.login,
                    id: user.id
                });
            } catch (error) {
                const err = error as Error;
                console.error('Error processing GitHub OAuth:', err);
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

            this.updateFiles(true);
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
        this.app.get('/openbmclapi/files', async (req: Request, res: Response) => {
            if (this.isUpdating) {
                res.status(503).send('File list update in progress');
                return;
            }
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
                res.send(await Utilities.getAvroBytes(files));
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
        this.app.get('/openbmclapi/download/:hash([0-9a-fA-F]*)', (req: Request, res: Response) => {
            if (!Utilities.verifyClusterRequest(req)) {
                res.status(403).send(); // 禁止访问
                return;
            }
            if (this.isUpdating) {
                res.status(503).send('File list update in progress');
                return;
            }
            const hash = req.params.hash.toLowerCase();
            const file = this.files.find(f => f.hash === hash);
            if (file) {
                res.sendFile(file.path.substring(1), {
                    root: ".",
                    maxAge: "30d"
                });
            } else {
                res.status(404).send();
            }
        });
        this.app.get('/files/*', (req: Request, res: Response) => {
            if (this.isUpdating) {
                res.status(503).send('File list update in progress');
                return;
            }
            const p = decodeURI(req.path);
            const file = this.files.find(f => f.path === p);
            if (file) {
                let cluster = Utilities.getRandomElement(this.clusters.filter(c => c.isOnline));
                if (!cluster) {
                    res.sendFile(file.path.substring(1), {
                        root: ".",
                        maxAge: "30d"
                    }, (err) => {
                        if (err) {
                            const availablePlugins = this.plugins.filter(p => p.exists(file));
                            if (availablePlugins.length > 0) {
                                Utilities.getRandomElement(this.plugins)?.express(file, req, res);
                                this.centerStats.addData({ hits: 1, bytes: file.size });
                                return;
                            } else {
                                res.status(404).send("The requested file is not found or is not accessible.");
                                return;
                            }
                        }
                    });
                    return;
                }

                res.status(302)
                .header('Location', Utilities.getUrl(file, cluster))
                .send();
                this.centerStats.addData({ hits: 1, bytes: file.size });
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
                }),
                today: this.centerStats.today(),
                onlines: this.clusters.filter(c => c.isOnline).length,
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
                .map(c => c.getJson(true, true));
        
            const offlineClustersSorted = offlineClusters
                .sort((a, b) => b.traffic - a.traffic)
                .map(c => c.getJson(true, true));
        
            // 添加 ownerName 并返回 JSON 响应
            const result = onlineClustersSorted.concat(offlineClustersSorted).map(c => {
                return {
                    ...c,
                    ownerName: this.db.getEntity<UserEntity>(UserEntity, c.owner)?.username || ''
                }
            });
            
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
                avatar_url: user.photo,
                is_super_admin: Boolean(user.isSuperUser)
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
            res.status(200).json(matches.map(c => c.getJson(true, false)));
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
            res.status(200).json(matches.map(c => c.getJson(true, false)));
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
                res.status(200).json(clusters.map(c => c.getJson(true, false)));
            } else {
                const cluster = this.clusters.find(c => c.clusterId === clusterId && c.owner === user.id);
                if (!cluster) {
                    res.status(404).send(); // 集群不存在
                    return;
                }
                res.status(200).json(cluster.getJson(true, false));
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
            res.status(200).json(cluster.getJson(true, false));
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
        this.app.get('/93AtHome/random', (req: Request, res: Response) => {
            res.status(302);
            res.setHeader('Location', Utilities.getRandomElement(this.files)?.path || '');
            res.send();
        });
        this.app.post('/openbmclapi/report', (req: Request, res: Response) => {
            const body = req.body as {
                urls: string[],
                error: string
            };
            res.status(200).send();
        });
        this.app.post('/93AtHome/super/cluster/create', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const clusterName = req.body.clusterName as string;
            const bandwidth = req.body.bandwidth as number;

            let cluster = new ClusterEntity();
            cluster.clusterId = Utilities.generateRandomString(24);
            cluster.clusterSecret = Utilities.generateRandomString(32);
            cluster.clusterName = clusterName;
            cluster.bandwidth = bandwidth;
            cluster.port = 0;
            cluster.owner = 0;
            cluster.traffic = 0;
            cluster.hits = 0;
            cluster.isOnline = false;
            cluster.downReason = "null";
            cluster.createdAt = Math.floor(Date.now() / 1000);
            this.db.insert(cluster);
            this.clusters.push(cluster);
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json(cluster.getJson(false, false));
        });
        this.app.post('/93AtHome/super/cluster/remove', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const clusterId = req.body.clusterId as string;
            const cluster = this.clusters.find(c => c.clusterId === clusterId);
            if (!cluster) {
                res.status(404).send({
                    success: false,
                    message: "Cluster not found"
                }); // 集群不存在
                return;
            }
            this.db.remove<ClusterEntity>(ClusterEntity, cluster);
            this.clusters = this.clusters.filter(c => c.clusterId !== clusterId);
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json({
                success: true
            });
        });
        this.app.post('/93AtHome/super/cluster/ban', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const data = req.body as {
                clusterId: string,
                ban: boolean
            };
            const cluster = this.clusters.find(c => c.clusterId === data.clusterId);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            cluster.isBanned = Number(data.ban);
            this.db.update(cluster);
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json(cluster.getJson(true, false));
        });
        this.app.post('/93AtHome/super/cluster/profile', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const userId = JwtHelper.getInstance().verifyToken(req.cookies.token, 'user') as { userId: number };
            const clusterId = req.query.clusterId as string;
            const clusterName = req.body.clusterName as string || null;
            const bandwidth = req.body.bandwidth as number || null;
            const sponsor = req.body.sponsor as string || null;
            const sponsorUrl = req.body.sponsorUrl as string || null;

            const cluster = this.clusters.find(c => c.clusterId === clusterId);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }

            if (clusterName) cluster.clusterName = clusterName;
            if (bandwidth) cluster.bandwidth = bandwidth;
            if (sponsor) cluster.sponsor = sponsor;
            if (sponsorUrl) cluster.sponsorUrl = sponsorUrl;

            this.db.update(cluster);
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json(cluster.getJson(true, false));
        });
        this.app.get('/93AtHome/syncSources', (req: Request, res: Response) => res.status(200).json(this.sources));
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

            socket.on('enable', (data, callback: Function) => {
                const ack = callback ? callback : (...rest: any[]) => {};
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

                if (this.isUpdating) {
                    ack({ message: "File list is updating, please try again later."});
                    return;
                }

                const randomFileCount = 5;
                const randomFiles = Utilities.getRandomElements(this.files, randomFileCount);
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster) {
                    ack({ message: "Cluster not found."});
                    return;
                }

                if (cluster.isBanned) {
                    ack({ message: "This cluster is banned."});
                    return;
                }

                cluster.endpoint = enableData.host;
                cluster.port = enableData.port;
                cluster.version = enableData.version;

                Utilities.checkSpecfiedFiles(randomFiles, cluster)
                .then(message => {
                    if (message) {
                        ack({ message: message });
                        return;
                    } else {
                        cluster.doOnline(this.files);
                        this.db.update(cluster);
                        ack([null, true]);
                    }
                })
                .catch(err => {
                    ack({ message: err.message });
                    console.error(err);
                });
            });

            socket.on('keep-alive', (data, callback: Function) => {
                const ack = callback ? callback : (...rest: any[]) => {};
                const keepAliveData = data as  {
                    time: string,
                    hits: number,
                    bytes: number
                };

                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster || !cluster?.isOnline || cluster?.isBanned) {
                    if (!cluster?.isOnline) {
                        socket.send(`Your cluster was kicked by server because: ${cluster?.downReason}`);
                    }
                    else if (cluster?.isBanned) {
                        socket.send("This cluster is banned.");
                    }
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

            socket.on('disable', (data, callback: Function) => {
                const ack = callback ? callback : (...rest: any[]) => {};
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster || !cluster.isOnline) {
                    ack([null, false]);
                }
                else {
                    console.log(`SOCKET ${socket.handshake.url} socket.io <DISABLE> - [${socket.handshake.headers["x-real-ip"] || socket.handshake.address}] ${socket.handshake.headers['user-agent']}`);
                    cluster.doOffline("Client disabled");
                    socket.send('Bye. Have a good day!');
                    cluster.downTime = Math.floor(Date.now() / 1000);
                    ack([null, true]);
                    this.db.update(cluster);
                }
            });

            socket.on('disconnect', () => {
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (cluster) {
                    console.log(`SOCKET ${socket.handshake.url} socket.io <DISCONNECTED> - [${socket.handshake.headers["x-real-ip"] || socket.handshake.address}] ${socket.handshake.headers['user-agent']}`);
                    if (cluster.isOnline) {
                        cluster.downReason = "Client disconnected";
                        cluster.downTime = Math.floor(Date.now() / 1000);
                        cluster.doOffline("Client disconnected")
                        this.db.update(cluster);
                    }
                }
            })
        });
    }
}
