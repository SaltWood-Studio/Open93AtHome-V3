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
import {type Got} from 'got'
import acme from 'acme-client'
import { FileList } from './FileList.js';
import RateLimiter, { rateLimiter } from './RateLimiter.js';
import { CertificateObject } from './database/Certificate.js';
import { DnsManager } from './certificate-manager/DnsManager.js';
import { CloudFlare } from './certificate-manager/CloudFlare.js';
import { DNSPod } from './certificate-manager/DNSPod.js';
import { ACME } from './certificate-manager/ACME.js';
import { ApiFactory } from './routes/ApiFactory.js';
require("express-async-errors");

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
    public app;
    public io: SocketIOServer;
    private httpServer;
    public db: SQLiteHelper;
    protected fileList: FileList;
    public isUpdating: boolean = false;
    protected sessionToClusterMap: Map<string, ClusterEntity> = new Map();
    public stats: StatsStorage[];
    public centerStats: HourlyStatsStorage;
    protected plugins: Plugin[];
    protected pluginLoader: PluginLoader;
    public got: Got;
    protected sources: { name: string, count: number, lastUpdated: Date, isFromPlugin: boolean }[] = [];
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
        this.startAt = new Date();
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
        // 设置中间件
        if (!Config.instance.disableAccessLog) this.app.use(logMiddleware);
        if (Config.instance.requestRateLimit > 0) this.app.use(rateLimiter);
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(cookieParser());
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
        this.httpServer.listen(Config.instance.port, () => {
          console.log(`HTTP Server running on http://localhost:${Config.instance.port}`);
        });
    }

    public setupRoutes(): void {
        this.setupHttp();
        this.setupSocketIO();
        if (Config.instance.debug) this.setupDebugRoutes();
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
            res.end(JSON.stringify(Array.from(this.io.sockets.sockets).map(([id, socket]) => ({
                session: id,
                ip: getRealIP(socket.handshake.headers) || socket.handshake.address,
                cluster: this.sessionToClusterMap.get(id)?.getJson(true, true)
            }))));
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
        const factory = new ApiFactory(this, this.fileList, this.db, this.dns, this.acme, this.app);
        factory.factory();

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
        this.app.get('/files/*', async (req: Request, res: Response) => {
            try {
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
                    let cluster = await this.fileList.randomAvailableCluster(file, file.url ? undefined : this.fileList.clusters.filter(c => !c.isProxyCluster), getRealIP(req.headers) || req.ip);
                    if (!cluster) {
                        this.sendFile(req, res, file);
                        return;
                    }

                    if (file.url && cluster.isProxyCluster) {
                        const url = `${Utilities.getUrlByPath(file.url, `/download`, cluster)}&origin=${encodeURIComponent(file.url)}`;
                        res.redirect(url);
                    }
                    else res.redirect(Utilities.getUrl(file, cluster));

                    if (cluster.masterStatsMode) {
                        this.stats.filter(s => s.id === cluster.clusterId).forEach(s => s.addData({ hits: 1, bytes: file.size }));
                        this.centerStats.addData({ hits: 1, bytes: file.size });
                    }
                    else {
                        cluster.pendingHits++;
                        cluster.pendingTraffic += file.size;
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
                    if (Config.instance.debug) {
                        console.debug(`Received event "${event}" with data ${JSON.stringify(data)}.`);
                    }
                    try {
                        await fn(callback, ...data);
                    }
                    catch (error) {
                        try {
                            socket.emit("error", error);
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

                if (Config.instance.debug && adminToken) {
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
                    console.log(`SOCKET [${socket.id}] <ADMIN> - [${getRealIP(socket.handshake.headers) || socket.handshake.address}] <${socket.handshake.headers['user-agent'] || 'null'}>`);
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
                        console.log(`SOCKET ${socket.id} <ACCEPTED> - [${getRealIP(socket.handshake.headers) || socket.handshake.address}] <${socket.handshake.headers['user-agent'] || 'null'}>`);
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
            console.log(`SOCKET [${this.sessionToClusterMap.get(socket.id)?.clusterId}] <CONNECTED> - [${getRealIP(socket.handshake.headers) || socket.handshake.address}] <${socket.handshake.headers['user-agent'] || 'null'}>`);

            socket.onAny((event: string, data) => {
                if (this.sessionToClusterMap.has(socket.id)) {
                    console.log(`SOCKET [${this.sessionToClusterMap.get(socket.id)?.clusterId}] <${event?.toUpperCase() || 'UNKNOWN'}> - [${getRealIP(socket.handshake.headers) || socket.handshake.address}] <${socket.handshake.headers['user-agent'] || 'null'}> ${`<WITH ${Object.keys(data || []).length || 'NO'} PARAMS>`}`);
                }
            });

            wrapper(socket, "enable", async (ack: Function, data: any) => {
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
                    ack([{message: "File list is updating, please try again later."}, false]);
                    return;
                }

                const randomFileCount = 5;
                const randomFiles = Utilities.getRandomElements(this.files, randomFileCount);
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster) {
                    ack([{message: "Cluster not found."}, false]);
                    return;
                }

                if (Config.instance.failAttemptsToBan > 0 && Config.instance.failAttemptsDuration > 0) {
                    Utilities.filterMinutes(cluster.enableHistory, Config.instance.failAttemptsDuration);
                    if (cluster.enableHistory.length >= Config.instance.failAttemptsToBan) {
                        ack(["Error: Too many failed enable requests. This cluster is now banned."]);
                        cluster.isBanned = true;
                        cluster.doOffline("Too many failed enable requests. This cluster is now banned.");
                        this.db.update(cluster);
                        return;
                    }
                    cluster.enableHistory.push(new Date());
                }

                if (cluster.isBanned) {
                    ack([{message: "This cluster is banned."}, false]);
                    return;
                }
                
                const address = (socket.handshake.headers[Config.instance.sourceIpHeader] as string).split(',').at(0) || socket.handshake.address;

                if (enableData.byoc) {
                    cluster.endpoint = enableData.host;
                }
                else if (this.dns) {
                    const domain = Config.instance.dnsDomain;
                    const subDomain = `${cluster.clusterId}.cluster`;

                    cluster.endpoint = `${cluster.clusterId}.cluster.${Config.instance.dnsDomain}`;

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
                        ack([{message: `Failed to add DNS record for "${enableData.host || address}". Please contact admin.`}, false]);
                        return;
                    }
                    console.log(`Adding A record for cluster ${cluster.clusterId}, address "${address}".`);

                    this.db.update(cluster);
                }
                else {
                    ack([{message: "DNS is not enabled, so you must enable \"Bring Your Own Certificate\" and provide the endpoint."}, false]);
                    return;
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

                const tip = `Cluster ${cluster.clusterId} is now ready at ${cluster.endpoint}. If this is your first time enabling this cluster or the ${enableData.byoc ? "domain's record" : (!enableData.byoc && enableData.host ? `CNAME destination (${enableData.host})` : `IP address (${address}:${enableData.port})`)} has changed, please allow a few minutes for the DNS records to update and propagate.`;

                if (Config.instance.noWarden){
                    cluster.doOnline(this.files, socket);
                    this.db.update(cluster);
                    socket.send(tip);
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
                        socket.send(tip);
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

            wrapper(socket, "keep-alive", (ack: Function, data: any) => {
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
                    if (cluster.masterStatsMode) {
                        ack([null, keepAliveData.time]);
                        return;
                    }
                    const hits = Math.min(keepAliveData.hits, cluster.pendingHits);
                    const traffic = Math.min(keepAliveData.bytes, cluster.pendingTraffic);
                    this.centerStats.addData({ hits: hits, bytes: traffic });
                    cluster.pendingHits = 0;
                    cluster.pendingTraffic = 0;
                    ack([null, keepAliveData.time]);
                    this.db.update(cluster);
                    this.stats.filter(c => c.id === cluster.clusterId).forEach(s => s.addData({ hits: Number(hits), bytes: Number(traffic) }));
                }
            });

            wrapper(socket, "disable", (ack: Function, ...data: any) => {
                const cluster = this.sessionToClusterMap.get(socket.id);

                if (!cluster || !cluster.isOnline) {
                    ack([null, false]);
                }
                else {
                    cluster.doOffline("Client disabled");
                    socket.send('Bye. Have a good day!');
                    ack([null, true]);
                    this.db.update(cluster);
                }
            });

            if (Config.instance.enableRequestCertificate) {
                wrapper(socket, "request-cert", async (ack: Function) => {

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
                        
                            console.log('Requesting certificate for', domain, subDomain, Config.instance.domainContactEmail);
                            const certificate = await this.acme.requestCertificate(domain, subDomain, Config.instance.domainContactEmail);

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
                    this.sessionToClusterMap.delete(socket.id);
                }
            });

            if (Config.instance.debug) {
                socket.on('run-sql', (data, callback: Function) => {
                    const ack = callback ? callback : (...rest: any[]) => {};
                    try {
                        const stmt = this.db.database.prepare(data);
                        let result = null;
                        if (stmt.reader) result = stmt.all();
                        else result = stmt.run();
                        ack(result);
                    }
                    catch (err) {
                        console.error(err);
                        ack({ error: err });
                    }
                });
            }
        });
    }
}
