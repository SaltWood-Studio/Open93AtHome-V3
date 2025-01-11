import express, { NextFunction, Request, Response } from 'express';
import http from 'http';
import fs from 'fs';
import path, { resolve } from 'path';
import { ExtendedError, Server as SocketIOServer } from 'socket.io';
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
import acme from 'acme-client'
import { FileList } from './FileList.js';
import RateLimiter, { rateLimiter } from './RateLimiter.js';
import { CertificateObject } from './database/Certificate.js';
import { DnsManager } from './certificate-manager/DnsManager.js';
import { CloudFlare } from './certificate-manager/CloudFlare.js';
import { DNSPod } from './certificate-manager/DNSPod.js';
import { ACME } from './certificate-manager/ACME.js';
import { ApiFactory } from './routes/ApiFactory.js';

//@ts-ignore
await import("express-async-errors")

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
    console.log(`${req.method} ${req.originalUrl} ${req.protocol} <${res.statusCode}> - [${req.ip}] ${userAgent}`);
};

export class Server {
    public app;
    public io: SocketIOServer;
    private httpServer;
    public db: SQLiteHelper;
    protected fileList: FileList;
    public isUpdating: boolean = false;
    public sessionToClusterMap: Map<string, ClusterEntity> = new Map();
    public stats: StatsStorage[];
    public centerStats: HourlyStatsStorage;
    public plugins: Plugin[];
    protected pluginLoader: PluginLoader;
    public sources: { name: string, count: number, lastUpdated: Date, isFromPlugin: boolean }[] = [];
    protected dns: DnsManager | null = null;
    protected acme: ACME | null = null;
    public startAt: Date;
    
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
        this.startAt = Utilities.getDate();
        this.plugins = [];
        this.pluginLoader = new PluginLoader();

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
        // 设置中间件
        if (Config.instance.network.trustProxy) this.app.set('trust proxy', true);
        if (!Config.instance.dev.disableAccessLog) this.app.use(logMiddleware);
        if (Config.instance.security.requestRateLimit > 0) this.app.use(rateLimiter);
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(cookieParser());
        await this.loadPlugins();
        await this.updateFiles();
        this.setupRoutes();

        if (Config.instance.data.checkInterval > 0) setInterval(this.updateFiles.bind(this), Config.instance.data.checkInterval * 60 * 1000);

        // 加载证书管理器
        if (Config.instance.server.requestCert) {
            switch (Config.instance.dns.type) {
                case "cloudflare":
                    this.dns = new CloudFlare(Config.instance.dns.secretId, Config.instance.dns.secretToken, Config.instance.dns.domain);
                    break;
                case "dnspod":
                    this.dns = new DNSPod(Config.instance.dns.secretId, Config.instance.dns.secretToken, Config.instance.dns.domain);
                    break;
                default:
                    if (!Config.instance.dns.type) {
                        throw new Error("DNS type is not specified in \".env\" file. Specify DNS type in it or disable request certificate.");
                    }
                    else {
                        throw new Error(`Unsupported DNS type: ${Config.instance.dns.type}`);
                    }
            }
            console.log(`Certificate manager loaded. Using ${Config.instance.dns.type} DNS provider.`);

            // 检查 ./data/acme.key
            let buffer;
            if (fs.existsSync(resolve("./data/acme.key"))) {
                buffer = fs.readFileSync(resolve("./data/acme.key"));
            }
            else {
                // 生成 ./data/acme.key
                buffer = await acme.forge.createPrivateKey();
                fs.writeFileSync(resolve("./data/acme.key"), buffer);
            }
            this.acme = new ACME(this.dns, buffer);
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
        this.httpServer.listen(Config.instance.network.port, Config.instance.network.host, () => {
          console.log(`HTTP Server running on http://${Config.instance.network.host}:${Config.instance.network.port}`);
        });
    }

    public setupRoutes(): void {
        this.setupHttp();
        this.setupSocketIO();
    }

    public setupHttp(): void {
        this.app.get('/', (req: Request, res: Response) => {
            res.status(302).setHeader('Location', '/dashboard').send();
        });
        this.app.use('/assets', express.static(path.resolve('./assets')));

        // 废弃提示
        this.app.use("/93AtHome", (req: Request, res: Response) => {
            res.status(410).send("This API is deprecated and removed. Please use APIv2 instead.");
        });

        const factory = new ApiFactory(this, this.fileList, this.db, this.dns, this.acme, this.app);
        factory.factory(Config.instance.dev.debug);

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
        this.app.post('/openbmclapi-agent/token', (req: Request, res: Response) => {
            res.setHeader('Content-Type', 'application/json');
            // 从请求体中获取参数
            const clusterId = req.body.clusterId as string;
            const signature = req.body.signature as string;
            const challenge = req.body.challenge as string;

            if (req.body.token) {
                const token = String(req.body.token);
                const claims = JwtHelper.instance.verifyToken(token, 'cluster') as { clusterId: string };
                if (!this.clusters.some(c => c.clusterId === claims.clusterId)) {
                    res.status(401).json({ error: "Cluster not found. But, how did you done it?" });
                    return;
                }
                const newToken = JwtHelper.instance.issueToken(
                    { clusterId: clusterId },
                    'cluster',
                    60 * 60 * 24 // 过期时间：24小时
                );
                res.status(200).json({
                    token: newToken,
                    ttl: 1000 * 60 * 60 * 24
                });
                return;
            }

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
            console.log(`Available files for cluster ${clusterId}: ${cluster.shards} shards.`);

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
            res.status(200).json({ sync: { concurrency: Config.instance.server.concurrency, source: "center" }});
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
        this.app.post('/openbmclapi/report', (req: Request, res: Response) => {
            const body = req.body as {
                urls: string[],
                error: string
            };
            res.status(200).send();
        });
        this.app.get('/files/*', async (req: Request, res: Response) => {
            try {
                if (this.isUpdating) {
                    res.status(503).send('File list update in progress');
                    return;
                }
                const p = decodeURI(req.path);
                const file = this.fileList.getFile("path", p);
                if (file) {
                    if (Config.instance.server.forceNoOpen) {
                        this.sendFile(req, res, file);
                        return;
                    }
                    let cluster = await this.fileList.randomAvailableCluster(file, file.url ? undefined : this.fileList.clusters.filter(c => !c.isProxyCluster), req.ip);
                    if (!cluster) {
                        this.sendFile(req, res, file);
                        return;
                    }

                    else res.redirect(Utilities.getUrl(file, cluster));

                    if (cluster.masterStatsMode) {
                        this.stats.filter(s => s.id === cluster.clusterId).forEach(s => s.addData({ hits: 1, bytes: file.size }));
                        this.centerStats.addData({ hits: 1, bytes: file.size });
                    }
                    else {
                        cluster.pendingHits++;
                        cluster.pendingBytes += file.size;
                    }
                } else {
                    res.status(404).send();
                }
            } catch (error) {
                console.error(error);
                res.status(500).json(error);
            }
        });
    }

    public setupSocketIO(): void {
        const wrapper = function (socket: any, event: string, fn: Function) {
            socket.on(event, async (...rest: any[]) => {
                try {
                    let callback = rest.find((item) => typeof item === "function");
                    if (!callback) {
                        console.warn("No callback found in arguments");
                    }
                    callback = callback || ((...args: any[]) => {});
                    const data = callback ? rest.slice(0, rest.indexOf(callback)) : rest;
                    if (Config.instance.dev.debug) {
                        console.debug(`Received event "${event}" with data ${JSON.stringify(data)}.`);
                    }
                    try {
                        const result = await fn(...data);
                        // 如果不为 undefined
                        if (result === undefined) {
                            callback([null, false]);
                            return;
                        }
                        // 如果为数组
                        if (Array.isArray(result)) callback(result);
                        // 如果为对象
                        else callback([null, result]);
                    }
                    catch (error) {
                        try {
                            socket.emit("error", error);
                            callback([error, null])
                        } catch (e) { }
                    }
                } catch (error) {
                    console.error(error);
                }
            });
        };

        this.io.use((socket, next) => {
            try {
                const token = socket.handshake.auth?.token;
                const adminToken = socket.handshake.auth?.adminToken;
                if (!token && !adminToken) {
                    throw new Error('No token provided');
                }

                if (Config.instance.dev.debug && adminToken) {
                    if (!(JwtHelper.instance.verifyToken(adminToken, 'admin') instanceof Object)) {
                        throw new Error('Invalid admin token');
                    }
                    if (socket.handshake.auth.clientId) {
                        const cluster = this.clusters.find(c => c.clusterSecret === adminToken);
                        if (!cluster) {
                            throw new Error('Invalid admin token');
                        }
                        this.sessionToClusterMap.set(socket.id, cluster);
                        return next(); // 验证通过，允许连接
                    }
                    console.log(`SOCKET [${socket.id}] <ADMIN> - [${Utilities.getRealIP(socket.handshake.headers) || socket.handshake.address}] <${socket.handshake.headers['user-agent'] || 'null'}>`);
                    return next();
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
                        console.log(`SOCKET ${socket.id} <ACCEPTED> - [${Utilities.getRealIP(socket.handshake.headers) || socket.handshake.address}] <${socket.handshake.headers['user-agent'] || 'null'}>`);
                        return next(); // 验证通过，允许连接
                    } else {
                        throw new Error('Token expired');
                    }
                } else {
                    throw new Error('Token payload invalid');
                }
            } catch (err) {
                console.error(err);
                socket.disconnect(true);
                return next(err as ExtendedError); // 验证失败，拒绝连接
            }
        });

        // 监听 Socket.IO 连接事件
        this.io.on('connection', (socket) => {
            console.log(`SOCKET [${this.sessionToClusterMap.get(socket.id)?.clusterId}] <CONNECTED> - [${Utilities.getRealIP(socket.handshake.headers) || socket.handshake.address}] <${socket.handshake.headers['user-agent'] || 'null'}>`);

            socket.onAny((event: string, data) => {
                if (this.sessionToClusterMap.has(socket.id)) {
                    console.log(`SOCKET [${this.sessionToClusterMap.get(socket.id)?.clusterId}] <${event?.toUpperCase() || 'UNKNOWN'}> - [${Utilities.getRealIP(socket.handshake.headers) || socket.handshake.address}] <${socket.handshake.headers['user-agent'] || 'null'}> ${`<WITH ${Object.keys(data || []).length || 'NO'} PARAMS>`}`);
                    const cluster = this.sessionToClusterMap.get(socket.id);
                    if (cluster) {
                        cluster.lastSeen = Date.now();
                        this.db.update(cluster);
                    }
                }
            });

            wrapper(socket, "enable", async (data: any) => {
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

                if (this.isUpdating) throw new Error("File list is updating, please try again later.");

                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster) throw new Error('No cluster found');

                if (Config.instance.security.failAttemptsToBan > 0 && Config.instance.security.failAttemptsDuration > 0) {
                    Utilities.filterMinutes(cluster.enableHistory, Config.instance.security.failAttemptsDuration);
                    if (cluster.enableHistory.length >= Config.instance.security.failAttemptsToBan) {
                        cluster.isBanned = true;
                        cluster.doOffline("Too many failed enable requests. This cluster is now banned.");
                        this.db.update(cluster);
                        throw new Error("Error: Too many failed enable requests. This cluster is now banned.");
                    }
                    cluster.enableHistory.push(new Date());
                }

                if (cluster.isBanned) {
                    throw new Error("Error: This cluster is banned.");
                }
                
                const address = (socket.handshake.headers[Config.instance.dev.sourceIpHeader] as string).split(',').at(0) || socket.handshake.address;

                if (enableData.byoc) {
                    cluster.endpoint = enableData.host;
                }
                else if (this.dns) {
                    const domain = Config.instance.dns.domain;
                    const subDomain = `${cluster.clusterId}.cluster`;

                    cluster.endpoint = `${cluster.clusterId}.cluster.${Config.instance.dns.domain}`;

                    try { await this.dns.removeRecord(subDomain, "A"); } catch (error) {}
                    try { await this.dns.removeRecord(subDomain, "CNAME"); } catch (error) {}

                    try {
                        if (enableData.host) {
                            await this.dns.addRecord(subDomain, enableData.host, "CNAME");
                        }
                        else await this.dns.addRecord(subDomain,  address, "A");
                    }
                    catch (error) {
                        console.error(error);
                        throw new Error(`Failed to add DNS record for "${enableData.host || address}". Please contact admin.`);
                    }
                    console.log(`Adding record for cluster ${cluster.clusterId}, address "${address}".`);

                    this.db.update(cluster);
                }
                else throw new Error("DNS is not enabled, so you must enable \"Bring Your Own Certificate\" and provide the endpoint.");
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

                const tip = `Cluster ${cluster.clusterId} is now ready at ${cluster.endpoint}. If this is your first time enabling this cluster or the ${enableData.byoc ? "domain's record" : (!enableData.byoc && enableData.host ? `CNAME destination (${enableData.host})` : `IP address (${address}:${enableData.port})`)} has changed, please allow a few minutes for the DNS records to update and propagate.`;

                if (Config.instance.server.noWarden || cluster.noWardenMode){
                    socket.send(tip);
                    cluster.doOnline(this.files, socket, true);
                    this.db.update(cluster);
                    return true;
                }

                const randomFileCount = 5;
                const randomFiles = Utilities.getRandomElements(this.fileList.getAvailableFiles(cluster), randomFileCount);

                const message = await Utilities.checkSpecfiedFiles(randomFiles, cluster);
                if (message) throw new Error(message);
                else {
                    socket.send(tip);
                    cluster.doOnline(this.fileList.getAvailableFiles(cluster), socket);
                    this.db.update(cluster);
                    cluster.enableHistory = [];
                    return true;
                }
            });

            wrapper(socket, "keep-alive", (data: any) => {
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
                    return false;
                }
                else {
                    if (cluster.masterStatsMode) {
                        return keepAliveData.time;
                    }
                    const hits = Math.min(keepAliveData.hits, cluster.pendingHits);
                    const bytes = Math.min(keepAliveData.bytes, cluster.pendingBytes);
                    this.centerStats.addData({ hits: hits, bytes: bytes });
                    cluster.pendingHits = 0;
                    cluster.pendingBytes = 0;
                    this.db.update(cluster);
                    this.stats.filter(c => c.id === cluster.clusterId).forEach(s => s.addData({ hits: Number(hits), bytes: Number(bytes) }));
                    return keepAliveData.time;
                }
            });

            wrapper(socket, "disable", (...data: any) => {
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster || !cluster.isOnline) {
                    return false;
                }
                else {
                    cluster.doOffline("Client disabled");
                    socket.send('Bye. Have a good day!');
                    this.db.update(cluster);
                    return true;
                }
            });

            if (Config.instance.server.requestCert) {
                wrapper(socket, "request-cert", async () => {

                    const cluster = this.sessionToClusterMap.get(socket.id);

                    if (!cluster) {
                        return false;
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
                                throw new Error("Request-Certificate is not enabled. Please contact admin.");
                            }

                            const domain = Config.instance.dns.domain;
                            const subDomain = `${cluster.clusterId}.cluster`;

                            console.log('Removing old TXT records for', domain, `_acme-challenge.${subDomain}`);
                            try { await this.dns.removeRecord(`_acme-challenge.${subDomain}`, "TXT"); } catch (error) {}
                        
                            console.log('Requesting certificate for', domain, subDomain, Config.instance.dns.contactEmail);
                            const certificate = await this.acme.requestCertificate(domain, subDomain, Config.instance.dns.contactEmail);

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
                        console.error(e);
                    }
                    finally {
                        if (err) throw err;
                        else return cert;
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
                    this.sessionToClusterMap.delete(socket.id);
                }
            });

            if (Config.instance.dev.debug) {
                socket.on('run-sql', (data) => {
                    try {
                        const stmt = this.db.database.prepare(data);
                        let result = null;
                        if (stmt.reader) result = stmt.all();
                        else result = stmt.run();
                        return result;
                    }
                    catch (err) {
                        console.error(err);
                        throw err;
                    }
                });
            }
        });
    }
}
