import express, { NextFunction, Request, Response } from 'express';
import http from 'http';
import fs from 'fs';
import path, { resolve } from 'path';
import { Server as SocketIOServer } from 'socket.io';
// import cors from 'cors';
import JwtHelper from './JwtHelper.js';
import { SQLiteHelper } from './SQLiteHelper.js';
import { UserEntity } from './database/User.js';
import { ClusterEntity } from './database/Cluster.js';
import { Config } from './Config.js';
import { GitHubUser } from './database/GitHubUser.js';
import { File } from './database/File.js';
import { Utilities } from './Utilities.js';
import { StatsStorage } from './statistics/ClusterStats.js';
import { HourlyStatsStorage } from './statistics/HourlyStats.js';
import cookieParser from 'cookie-parser';
import { Plugin } from './plugin/Plugin.js';
import { PluginLoader } from './plugin/PluginLoader.js';
import {type Got} from 'got'
import acme from 'acme-client'
import { FileList } from './FileList.js';
import { rateLimiter } from './RateLimit.js';
import { CertificateObject } from './database/Certificate.js';
import { DnsManager } from './certificate-manager/DnsManager.js';
import { CloudFlare } from './certificate-manager/CloudFlare.js';
import { DNSPod } from './certificate-manager/DNSPod.js';
import { ACME } from './certificate-manager/ACME.js';

type Indexable<T> = {
    [key: string]: T;
}

// 创建一个中间件函数
const logMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // 调用下一个中间件
    next();

    // 在响应完成后记录访问日志
    res.on('finish', () => {
        logAccess(req, res);
    });
};

const getRealIP = (obj: Indexable<any>): string => {
    return (obj[Config.instance.sourceIpHeader] as string).split(',')[0];
}

const logAccess = (req: Request, res: Response) => {
    const userAgent = req.headers['user-agent'] || '';
    const ip = getRealIP(req.headers) || req.ip;
    console.log(`${req.method} ${req.originalUrl} ${req.protocol} <${res.statusCode}> - [${ip}] ${userAgent}`);
};

export class Server {
    private app;
    public io: SocketIOServer;
    private httpServer;
    public db: SQLiteHelper;
    protected fileList: FileList;
    protected isUpdating: boolean = false;
    protected sessionToClusterMap: Map<string, ClusterEntity> = new Map();
    public stats: StatsStorage[];
    public centerStats: HourlyStatsStorage;
    protected plugins: Plugin[];
    protected pluginLoader: PluginLoader;
    protected got: Got;
    protected sources: { name: string, count: number, lastUpdated: Date, isFromPlugin: boolean }[] = [];
    protected dns: DnsManager | null = null;
    protected acme: ACME | null = null;
    
    protected get files(): File[] {
        return this.fileList.files;
    }

    protected set files(files: File[]) {
        this.fileList.files = files;
    }
    
    protected get clusters(): ClusterEntity[] {
        return this.fileList.clusters;
    }

    protected set clusters(clusters: ClusterEntity[]) {
        this.fileList.clusters = clusters;
    }

    public constructor() {
        this.plugins = [];
        this.pluginLoader = new PluginLoader();

        this.got = Utilities.got;

        // 创建 Express 应用
        this.app = express();

        // 创建文件夹
        if (!fs.existsSync('./data')) fs.mkdirSync('./data');
        if (!fs.existsSync('./files')) fs.mkdirSync('./files');
        this.db = new SQLiteHelper("./data/database.sqlite");

        this.db.createTable<UserEntity>(UserEntity);
        this.db.createTable<ClusterEntity>(ClusterEntity);
        this.db.createTable<CertificateObject>(CertificateObject);
        this.stats = this.db.getEntities<ClusterEntity>(ClusterEntity).map(c => new StatsStorage(c.clusterId));
        this.centerStats = new HourlyStatsStorage();

        this.fileList = new FileList(undefined, this.db.getEntities<ClusterEntity>(ClusterEntity));

        // 创建 HTTP 服务器
        this.httpServer = http.createServer(this.app);

        // 创建 Socket.IO 服务器
        this.io = new SocketIOServer(this.httpServer, {
            cors: {
                origin: '*',
                methods: ['GET', 'POST']
            }
        });
    }
    
    private sendFile(req: Request, res: Response, file: File) {
        const availablePlugins = this.plugins.filter(p => p.exists(file));
        if (availablePlugins.length > 0) {
            Utilities.getRandomElement(this.plugins)?.express(file, req, res);
            this.centerStats.addData({ hits: 1, bytes: file.size });
            return;
        }
        res.sendFile(file.path.substring(1), {
            root: ".",
            maxAge: "30d"
        }, (err) => {
            if (!err) this.centerStats.addData({ hits: 1, bytes: file.size });
        });
    }

    public async init(): Promise<void> {
        await this.loadPlugins();
        await this.updateFiles();
        this.setupRoutes();

        // 加载证书管理器
        if (Config.instance.enableRequestCertificate) {
            switch (Config.instance.dnsType) {
                case "cloudflare":
                    this.dns = new CloudFlare(Config.instance.dnsSecretId, Config.instance.dnsSecretToken, Config.instance.dnsDomain);
                    break;
                case "dnspod":
                    this.dns = new DNSPod(Config.instance.dnsSecretId, Config.instance.dnsSecretToken, Config.instance.dnsDomain);
                    break;
                default:
                    if (!Config.instance.dnsType) {
                        throw new Error("DNS type is not specified in \".env\" file. Specify DNS type in it or disable request certificate.");
                    }
                    else {
                        throw new Error(`Unsupported DNS type: ${Config.instance.dnsType}`);
                    }
            }
            console.log(`Certificate manager loaded. Using ${Config.instance.dnsType} DNS provider.`);
            this.acme = new ACME(this.dns, await acme.crypto.createPrivateKey());
        }
    }

    public async loadPlugins(): Promise<void> {
        await this.pluginLoader.loadPlugins(this)
        .then(plugins => {
            this.plugins = plugins;
            plugins.forEach(plugin => plugin.init());
        })
        .catch(error => console.error(error));
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
            console.log(`...file list was successfully updated. Found ${this.files.length} files`);
            this.isUpdating = false;
            if (checkClusters) {
                const wardenPromises = this.clusters.filter(c => c.isOnline).map(async cluster => {
                    const message = await Utilities.checkSpecfiedFiles(Utilities.findDifferences(oldFiles, this.files, true), cluster); // 只查找新增的文件，不然删文件会把全部节点踢了
                    if (message) {
                        cluster.downReason = message;
                        cluster.isOnline = false;
                        this.db.update(cluster);
                        console.log(`Cluster ${cluster.clusterId} is down because of ${message}`);
                    }
                });
                await Promise.all(wardenPromises);
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
        this.httpServer.listen(Config.instance.port, () => {
          console.log(`HTTP Server running on http://localhost:${Config.instance.port}`);
        });
    }

    public setupRoutes(): void {
        this.setupHttp();
        this.setupSocketIO();
        if (Config.instance.enableDebugRoutes) this.setupDebugRoutes();
    }

    public setupDebugRoutes(): void {
        // 认证中间件
        const authMiddleware = (req: Request, res: Response, next: Function) => {
            if (Utilities.verifyAdmin(req, res, this.db)) {
                next();
            } else {
                res.status(403).json({ message: 'Forbidden' }); // 验证失败，返回 403 错误
            }
        };

        // 统一使用 authMiddleware 中间件来验证
        this.app.use('/93AtHome/debug', authMiddleware);

        this.app.get('/93AtHome/debug/list_plugins', async (req: Request, res: Response) => {
            const promises = this.plugins.map(async p => ({
                name: p.getName(),
                fileCount: (await p.getFiles()).length
            }));
            res.status(200).json(await Promise.all(promises));
        });
        this.app.get('/93AtHome/debug/all', (req: Request, res: Response) => {
            res.status(200).json({
                clusters: this.clusters.map(c => c.getJson(true, true)),
                sources: this.sources,
                plugins: this.plugins
            })
        })
        this.app.get('/93AtHome/debug/list_sessions', (req: Request, res: Response) => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(Array.from(this.sessionToClusterMap.entries())));
        });
        this.app.post('/93AtHome/debug/test_all_cluster', (req: Request, res: Response) => {
            const hash = req.body.hash as string;
            const file = this.fileList.getFile("hash", hash);
            if (!file) {
                res.status(404).json({ message: 'File not found' });
                return;
            }
            res.status(200).json(this.fileList.getAvailableClusters(file).map(c => ({
                clusterId: c.clusterId,
                requestUrl: Utilities.getUrl(file, c)
            })));
        })
        this.app.get('/93AtHome/debug/get_shard', (req: Request, res: Response) => {
            const hash = req.query.hash as string;
            const file = this.fileList.getFile("hash", hash);
            if (!file) {
                res.status(404).json({ message: 'File not found' });
                return;
            }
            res.status(200).json({
                shard: FileList.getShardIndex(file.path, FileList.SHARD_COUNT),
                file
            });
        });
        this.app.get('/93AtHome/debug/get_available_files', (req: Request, res: Response) => {
            const clusterId = req.query.clusterId as string;
            const cluster = this.clusters.find(c => c.clusterId === clusterId);
            if (!cluster) {
                res.status(404).json({ message: 'Cluster not found' });
                return;
            }
            res.status(200).json(this.fileList.getAvailableFiles(cluster));
        });
    }

    public setupHttp(): void {
        // 设置中间件
        this.app.use(logMiddleware);
        if (Config.instance.requestRateLimit > 0) this.app.use(rateLimiter);
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(cookieParser());

        this.app.use('/assets', express.static(path.resolve('./assets')));

        // 设置路由
        this.app.get('/', (req: Request, res: Response) => {
            res.status(302).setHeader('Location', '/dashboard').send();
        });
        this.app.get('/93AtHome/list_clusters', (req: Request, res: Response) => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(this.db.getEntities<ClusterEntity>(ClusterEntity).map(c => c.getJson(true, true))));
        });
        this.app.get('/93AtHome/list_files', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(this.files));
        });
        this.app.get('/93AtHome/dashboard/oauth_id', (req: Request, res: Response) => {
            res.statusCode = 200;
            res.end(Config.instance.githubOAuthClientId);
        });
        this.app.get('/93AtHome/dashboard/user/oauth', async (req: Request, res: Response) => {
            res.set("Content-Type", "application/json");
        
            try {
                const code = req.query.code as string || '';
        
                // 请求GitHub获取access_token
                const tokenData = await this.got.post(`https://${Config.instance.githubUrl}/login/oauth/access_token`, {
                    form: {
                        code,
                        client_id: Config.instance.githubOAuthClientId,
                        client_secret: Config.instance.githubOAuthClientSecret
                    },
                    headers: {
                        'Accept': 'application/json'
                    },
                    responseType: 'json'
                }).json<{ access_token: string }>();
        
                const accessToken = tokenData.access_token;
        
                let userResponse = await this.got.get(`https://${Config.instance.githubApiUrl}/user`, {
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
                const token = JwtHelper.instance.issueToken({
                    userId: user.id,
                    clientId: Config.instance.githubOAuthClientId
                }, "user", 60 * 60 * 24);
        
                res.cookie('token', token, {
                    expires: new Date(Date.now() + 86400000), // 24小时后过期
                    secure: true,
                    sameSite: 'lax',
                });

                if (this.db.getEntity<UserEntity>(UserEntity, user.id)?.isSuperUser) {
                    const adminToken = JwtHelper.instance.issueToken({
                        userId: user.id,
                        clientId: Config.instance.githubOAuthClientId
                    }, "admin", 60 * 60 * 24);
                    res.cookie('adminToken', adminToken, {
                        expires: new Date(Date.now() + 86400000), // 24小时后过期
                        secure: true,
                        sameSite: 'lax',
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
        this.app.get('/93AtHome/update_files', (req: Request, res: Response) => {
            const token = req.query.token as string || '';
            if (token !== Config.instance.updateToken) {
                res.status(403).send(); // 禁止访问
                return;
            }
            if (this.isUpdating) {
                res.status(409).send('Update in progress');
                return;
            }

            this.updateFiles(true);
            res.status(204).send();
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
                const token = JwtHelper.instance.issueToken({
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
            const claims = JwtHelper.instance.verifyToken(challenge, 'cluster-challenge') as { clusterId: string };
            const cluster = this.clusters.find(c => c.clusterId === claims.clusterId);
        
            if (cluster) {

                if (claims && claims.clusterId === clusterId && Utilities.computeSignature(challenge, signature, cluster.clusterSecret)) {
                    const token = JwtHelper.instance.issueToken(
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
            const clusterId = Utilities.tryGetRequestCluster<{ clusterId: string }>(req)?.clusterId || "";
            const cluster = this.clusters.find(c => c.clusterId === clusterId);
            if (!cluster) {
                res.status(401).send();
                return;
            }
            res.setHeader('Content-Disposition', 'attachment; filename="files.avro"');
            
            let lastModified = Number(req.query.lastModified);
            lastModified = Number.isNaN(lastModified)? 0 : lastModified;
            console.log(`Available files for cluster ${clusterId}: ${cluster.availShards} shards, ${this.fileList.getAvailableFiles(cluster).length}`);

            if (lastModified === 0) {
                res.status(200).send(await Utilities.getAvroBytes(this.fileList.getAvailableFiles(cluster)));
            }
            else {
                const files = this.fileList.getAvailableFiles(cluster);
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
            res.status(200).json({ sync: { concurrency: Config.instance.concurrency, source: "center" }});
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
            const file = this.fileList.getFile("hash", hash);
            if (file) {
                this.sendFile(req, res, file);
                return;
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
            const file = this.fileList.getFile("path", p);
            if (file) {
                if (Config.instance.forceNoOpen) {
                    this.sendFile(req, res, file);
                    return;
                }
                let cluster = this.fileList.randomAvailableCluster(file);
                if (!cluster) {
                    this.sendFile(req, res, file);
                    return;
                }

                res.status(302)
                .header('Location', Utilities.getUrl(file, cluster))
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
            let dailyHits: number[] = [];
            let dailyBytes: number[] = [];
            data.forEach(d => {
                let hits = 0;
                let bytes = 0;
                d.filter(h => h !== null).forEach(h => {
                    hits += h.hits;
                    bytes += h.bytes;
                });
                dailyHits.push(hits);
                dailyBytes.push(bytes);
            });
            res.status(200).json({
                dailyHits,
                dailyBytes,
                today: this.centerStats.today(),
                hourly: data.at(0)?.map(hour => ([hour.hits, hour.bytes])) || [],
                onlines: this.clusters.filter(c => c.isOnline).length,
                sourceCount: this.sources.length,
                totalFiles: this.files.length,
                totalSize: this.files.reduce((acc, f) => acc + f.size, 0)
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
                .sort((a, b) => {
                    const aStat = this.stats.find(s => s.id === a.clusterId)?.getTodayStats();
                    const bStat = this.stats.find(s => s.id === b.clusterId)?.getTodayStats();
                    if (aStat && bStat) {
                        return bStat.bytes - aStat.bytes;
                    } else {
                        return 0;
                    }
                })
                .map(c => c.getJson(true, true));
        
            const offlineClustersSorted = offlineClusters
                .sort((a, b) => {
                    const aStat = this.stats.find(s => s.id === a.clusterId)?.getTodayStats();
                    const bStat = this.stats.find(s => s.id === b.clusterId)?.getTodayStats();
                    if (aStat && bStat) {
                        return bStat.bytes - aStat.bytes;
                    } else {
                        return 0;
                    }
                })
                .map(c => c.getJson(true, true));
        
            // 添加 ownerName 并返回 JSON 响应
            const result = onlineClustersSorted.concat(offlineClustersSorted).map(c => {
                const stat = this.stats.find(s => s.id === c.clusterId)?.getTodayStats();
                return {
                    ...c,
                    ownerName: this.db.getEntity<UserEntity>(UserEntity, c.owner)?.username || '',
                    hits: stat?.hits || 0,
                    traffic: stat?.bytes || 0
                }
            });
            
            try {
                res.setHeader('Content-Type', 'application/json');
                res.status(200).json(result);
            } catch (error) {
                console.error('Error processing rank request:', error);
                res.status(500).send();
                console.log(result);
                result.forEach(element => {
                    console.log(element);
                    console.log(JSON.stringify(element));
                });
            }
        });
        
        this.app.get('/93AtHome/dashboard/user/profile', (req: Request, res: Response) => {
            const token = req.cookies.token;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
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
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number, exp: number }).userId);
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
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
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
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
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
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
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
                if (bandwidth < 10 || bandwidth > 500) {
                    res.status(400).send({
                        message: "Bandwidth must be between 10 and 500"
                    });
                    return;
                }
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
        
        this.app.post('/93AtHome/dashboard/user/cluster/reset_secret', (req: Request, res: Response) => {
            const token = req.cookies.token;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
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
            res.setHeader('Location', encodeURI(Utilities.getRandomElement(this.files)?.path || ''));
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
            cluster.doOffline("This cluster is banned.");
            this.db.update(cluster);
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json(cluster.getJson(true, false));
        });
        this.app.post('/93AtHome/super/cluster/kick', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const clusterId = req.query.clusterId as string || "";
            const cluster = this.clusters.find(c => c.clusterId === clusterId);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            cluster.doOffline("Operator kicked this cluster.");
            this.db.update(cluster);
            res.status(200).json(cluster.getJson(true, false));
        });
        this.app.post('/93AtHome/super/cluster/profile', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const userId = JwtHelper.instance.verifyToken(req.cookies.token, 'user') as { userId: number };
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
            if (bandwidth) {
                if (bandwidth < 10 || bandwidth > 500) {
                    res.status(400).send({
                        message: "Bandwidth must be between 10 and 500"
                    });
                    return;
                }
                cluster.bandwidth = bandwidth;
            }
            if (sponsor) cluster.sponsor = sponsor;
            if (sponsorUrl) cluster.sponsorUrl = sponsorUrl;

            this.db.update(cluster);
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json(cluster.getJson(true, false));
        });
        this.app.get('/93AtHome/syncSources', (req: Request, res: Response) => {
            res.status(200).json(this.sources);
        });
        this.app.post('/93AtHome/super/sudo', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const user = this.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(req.cookies.adminToken, 'admin') as { userId: number }).userId);
            if (!user) {
                res.status(401).send();
                return;
            }
            const data = req.body as {
                id: number
            };
            const targetUser = this.db.getEntity<UserEntity>(UserEntity, data.id);
            if (!targetUser) {
                res.status(404).send(); // 用户不存在
                return;
            }
            if ((user.isSuperUser <= targetUser.isSuperUser) && user.id !== targetUser.id) {
                res.status(403).send({
                    message: `Permission denied: Your permission level is not high enough to perform this action.`
                });
                return;
            }
            const targetToken = JwtHelper.instance.issueToken({
                userId: targetUser.id,
                clientId: Config.instance.githubOAuthClientId
            }, 'user', 1 * 24 * 60 * 60);
            const newAdminToken = JwtHelper.instance.issueToken({
                userId: user.id,
                clientId: Config.instance.githubOAuthClientId
            }, 'admin', 1 * 24 * 60 * 60);
            res.cookie('token', targetToken, {
                expires: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000),
                secure: true,
                sameSite: 'lax'
            })
            .cookie('adminToken', newAdminToken, {
                expires: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000),
                secure: true,
                sameSite: 'lax'
            })
            .status(200).json({
                success: true,
                permission: user.isSuperUser,
                requirePermission: targetUser.isSuperUser,
                user,
                targetUser
            });
        });
        this.app.get('/93AtHome/super/list_users', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const users = this.db.getEntities<UserEntity>(UserEntity);
            res.status(200).json(users);
        })
        this.app.post('/93AtHome/super/update', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            if (this.isUpdating) {
                res.status(409).send({
                    message: "File list is updating, please try again later."
                });
                return;
            }
            this.updateFiles();
            res.status(204).send();
        });
        this.app.get('/93AtHome/shards', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            res.json(this.fileList.shards);
        });
        this.app.post('/93AtHome/super/modify_shards', (req: Request, res: Response) => {
            if (!Utilities.verifyAdmin(req, res, this.db)) return;
            const cluster = this.clusters.find(c => c.clusterId === req.query.clusterId);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            // 判断 shards 是不是在 int 范围内
            const shards = req.body.shards as number;
            if (shards < -2147483648 || shards > 2147483647) {
                res.status(400).send({
                    message: "Shards must be between -2147483648 and 2147483647"
                });
                return;
            }
            cluster.availShards = shards;
            this.db.update(cluster);
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json(cluster.getJson(true, false));
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
                const object = JwtHelper.instance.verifyToken(token, 'cluster');
        
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
            console.log(`SOCKET [${this.sessionToClusterMap.get(socket.id)?.clusterId}] <CONNECTED> - [${getRealIP(socket.handshake.headers) || socket.handshake.address}] ${socket.handshake.headers['user-agent'] || '<null>'}`);

            socket.onAny((event: string, data) => {
                if (this.sessionToClusterMap.has(socket.id)) {
                    console.log(`SOCKET [${this.sessionToClusterMap.get(socket.id)?.clusterId}] <${event?.toUpperCase() || 'UNKNOWN'}> - [${getRealIP(socket.handshake.headers) || socket.handshake.address}] ${socket.handshake.headers['user-agent'] || '<null>'} ${`<WITH ${Object.keys(data || []).length || 'NO'} PARAMS>`}`);
                }
            });

            socket.on('enable', (data, callback: Function) => {
                const ack = callback ? callback : (...rest: any[]) => {};
                const enableData = data as {
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
                    ack(["File list is updating, please try again later."]);
                    return;
                }

                const randomFileCount = 5;
                const randomFiles = Utilities.getRandomElements(this.files, randomFileCount);
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster) {
                    ack(["Cluster not found."]);
                    return;
                }

                if (Config.instance.failAttemptsToBan > 0 && Config.instance.failAttemptsDuration > 0) {
                    Utilities.filterMinutes(cluster.enableHistory, Config.instance.failAttemptsDuration);
                    if (cluster.enableHistory.length >= Config.instance.failAttemptsToBan) {
                        ack(["Error: Too many failed enable requests. This cluster is now banned."]);
                        cluster.isBanned = 1;
                        cluster.doOffline("Too many failed enable requests. This cluster is now banned.");
                        this.db.update(cluster);
                        return;
                    }
                    cluster.enableHistory.push(new Date());
                }

                if (cluster.isBanned) {
                    ack(["This cluster is banned."]);
                    return;
                }

                if (enableData.byoc) {
                    cluster.endpoint = enableData.host;
                }
                else {
                    cluster.endpoint = `${cluster.clusterId}.cluster.${Config.instance.dnsDomain}`;
                    this.db.update(cluster);
                }
                cluster.port = enableData.port;
                cluster.version = enableData.version;

                // const size = 20;
                // const url = Utilities.getUrlByPath(`/measure/${size}`, `/measure/${size}`, cluster);
                // Utilities.doMeasure(url)
                // .then(result => {
                //     if (!result || result < 10) {
                //         ack([`Error: Failed to measure bandwidth: Result is ${result} Mbps`]);
                //         return;
                //     }
                //     
                // })
                // .catch(err => {
                //     ack([err.message]);
                //     console.error(err);
                // });
                if (Config.instance.noWarden){
                    cluster.doOnline(this.files, socket);
                    this.db.update(cluster);
                    ack([null, true]);
                    return;
                }
                Utilities.checkSpecfiedFiles(randomFiles, cluster)
                .then(message => {
                    if (message) {
                        ack([message]);
                        return;
                    } else {
                        cluster.doOnline(this.files, socket);
                        this.db.update(cluster);
                        ack([null, true]);
                        cluster.enableHistory = [];
                        return;
                    }
                })
                .catch(err => {
                    ack([err.message]);
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
                        socket.send(`Your cluster was kicked by server because of: ${cluster?.downReason}`);
                    }
                    else if (cluster?.isBanned) {
                        socket.send("This cluster is banned.");
                        cluster.doOffline("This cluster is banned.");
                    }
                    ack([null, false]);
                }
                else {
                    const hits = Math.min(keepAliveData.hits, cluster.pendingHits);
                    const traffic = Math.min(keepAliveData.bytes, cluster.pendingTraffic);
                    this.centerStats.addData({ hits: hits, bytes: traffic });
                    cluster.pendingHits = 0;
                    cluster.pendingTraffic = 0;
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
                    cluster.doOffline("Client disabled");
                    socket.send('Bye. Have a good day!');
                    cluster.downTime = Math.floor(Date.now() / 1000);
                    ack([null, true]);
                    this.db.update(cluster);
                }
            });

            if (Config.instance.enableRequestCertificate) {
                socket.on('request-cert', async (callback: Function) => {
                    const ack = callback ? callback : (...rest: any[]) => {};

                    const cluster = this.sessionToClusterMap.get(socket.id);

                    if (!cluster) {
                        ack([null, false]);
                        return;
                    }

                    console.log(`Cluster ${cluster.clusterId} is trying to request a certificate.`);

                    let [err, cert]: [any | null, {cert: string, key: string} | null] = [null, null];
                    let validRecordFound = false;

                    try {
                        const record = this.db.getEntities<CertificateObject>(CertificateObject).find(c => c.clusterId === cluster.clusterId);

                        if (record) {
                            const certificate = record.certificate;
                            const key = record.key;
                            const csr = record.csr;
                            const date = record.validFrom;
                            const expires = record.expiresAt;
                            const now = Date.now();

                            if (now + (10 * 24 * 60 * 60 * 1000) > expires) {
                                socket.send("Certificate will expire in 10 days. Will generate a new one.");
                                validRecordFound = false;
                            }
                            else {
                                socket.send("Valid certificate found in database. Sending back to client.");
                                err = null;
                                cert = { cert: certificate, key };
                                validRecordFound = true;
                            }
                        }

                        if (!validRecordFound) {
                            if (!this.dns || !this.acme) {
                                return [{message: "Request-Certificate is not enabled. Please contact admin."}, null];
                            }

                            const domain = Config.instance.dnsDomain;
                            const subDomain = `${cluster.clusterId}.cluster`;

                            console.log('Removing old TXT records for', domain, `_acme-challenge.${subDomain}`);
                            try { await this.dns.removeRecord(`_acme-challenge.${subDomain}`, "TXT"); } catch (error) {}
                            try { await this.dns.removeRecord(subDomain, "A"); } catch (error) {}
                        
                            console.log('Requesting certificate for', domain, subDomain, Config.instance.domainContactEmail);
                            const certificate = await this.acme.requestCertificate(domain, subDomain, Config.instance.domainContactEmail);
                            
                            const address = (socket.handshake.headers[Config.instance.sourceIpHeader] as string).split(',').at(0) || socket.handshake.address;
                            console.log(`Adding A record for cluster ${cluster.clusterId}, address "${address}".`);
                            await this.dns.addRecord(subDomain,  address, "A");

                            const finalCertificate = CertificateObject.create(
                                cluster.clusterId,
                                certificate[0],
                                certificate[1],
                                certificate[2],
                                certificate[3],
                                certificate[4]
                            );

                            if (this.db.exists<CertificateObject>(finalCertificate)) {
                                this.db.update<CertificateObject>(finalCertificate);
                            }
                            else {
                                this.db.insert<CertificateObject>(finalCertificate);
                            }

                            err = null;
                            cert = { cert: finalCertificate.certificate, key: finalCertificate.key };
                        }
                    }
                    catch (e) {
                        err = e;
                    }
                    finally {
                        ack([err, cert]);
                    }
                });
            }

            socket.on('disconnect', () => {
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (cluster) {
                    if (cluster.isOnline) {
                        cluster.downReason = "Client disconnected";
                        cluster.downTime = Math.floor(Date.now() / 1000);
                        cluster.doOffline("Client disconnected")
                        this.db.update(cluster);
                    }
                }
            });
        });
    }
}
