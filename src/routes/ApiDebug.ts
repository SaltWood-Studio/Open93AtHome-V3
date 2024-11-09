import { ApiFactory } from "./ApiFactory.js";
import { Request, Response } from "express";
import { getRealIP } from "../Server.js";
import { Utilities } from "../Utilities.js";
import { FileList } from "../FileList.js";
import { Config } from "../Config.js";

export class ApiDebug {
    public static register(inst: ApiFactory) {
        // 认证中间件
        const authMiddleware = (req: Request, res: Response, next: Function) => {
            if (Utilities.verifyAdmin(req, res, inst.db)) {
                next();
            }
        };

        // 统一使用 authMiddleware 中间件来验证
        inst.app.use('/api/debug', authMiddleware);

        inst.app.get('/api/debug/config', (req: Request, res: Response) => {
            res.status(200).json(Config.instance);
        });
        inst.app.get('/api/debug/plugins', async (req: Request, res: Response) => {
            const promises = inst.server.plugins.map(async p => ({
                name: p.getName(),
                fileCount: (await p.getFiles()).length
            }));
            res.json(await Promise.all(promises));
        });
        inst.app.get('/api/debug/all', (req: Request, res: Response) => {
            res.status(200).json({
                clusters: inst.clusters.map(c => c.getJson(true, true)),
                sources: inst.server.sources,
                plugins: inst.server.plugins
            });
        })
        inst.app.get('/api/debug/sessions', (req: Request, res: Response) => {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(Array.from(inst.server.io.sockets.sockets).map(([id, socket]) => ({
                session: id,
                ip: getRealIP(socket.handshake.headers) || socket.handshake.address,
                cluster: inst.server.sessionToClusterMap.get(id)?.getJson(true, true)
            }))));
        });
        inst.app.post('/api/debug/test_all_cluster', (req: Request, res: Response) => {
            const hash = req.body.hash as string;
            const file = inst.fileList.getFile("hash", hash);
            if (!file) {
                res.status(404).json({ message: 'File not found' });
                return;
            }
            res.status(200).json(inst.fileList.getAvailableClusters(file).map(c => ({
                clusterId: c.clusterId,
                requestUrl: Utilities.getUrl(file, c)
            })));
        })
        inst.app.get('/api/debug/get_shard', (req: Request, res: Response) => {
            const hash = req.query.hash as string;
            const file = inst.fileList.getFile("hash", hash);
            if (!file) {
                res.status(404).json({ message: 'File not found' });
                return;
            }
            res.status(200).json({
                shard: FileList.getShardIndex(file.path, FileList.SHARD_COUNT),
                file
            });
        });
        inst.app.get('/api/debug/get_available_files', (req: Request, res: Response) => {
            const clusterId = req.query.clusterId as string;
            const cluster = inst.clusters.find(c => c.clusterId === clusterId);
            if (!cluster) {
                res.status(404).json({ message: 'Cluster not found' });
                return;
            }
            res.status(200).json(inst.fileList.getAvailableFiles(cluster));
        });
    }
}