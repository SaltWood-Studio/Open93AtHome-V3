import { UserEntity } from "../database/User.js";
import { FileList } from "../FileList.js";
import RateLimiter from "../RateLimiter.js";
import { ApiFactory } from "./ApiFactory.js";

export class ApiStats {
    public static register(inst: ApiFactory) {
        inst.app.get("/api/stats/cluster/:id", (req, res) => {
            res.setHeader('Content-Type', 'application/json');
            const clusterId = req.params.id;
            const cluster = inst.clusters.find(c => c.clusterId === clusterId);
            if (cluster) {
                const stats = inst.stats.find(s => s.id === clusterId);
                if (stats) {
                    const data = stats.getLast30DaysStats();
                    const dates = data.map(d => d.date);
                    const dailyHits: number[] = data.map(d => d.hits);
                    const dailyBytes: number[] = data.map(d => d.bytes);
                    res.status(200).json({dates, hits: dailyHits, bytes: dailyBytes});
                } else {
                    res.status(404).send({ message: "Stats not found. This should never happen, please contact administrator." });
                }
            } else {
                res.status(404).send({ message: "Cluster not found" });
            }
        });

        inst.app.get("/api/stats/center", (req, res) => {
            res.setHeader('Content-Type', 'application/json');
            const data = inst.server.centerStats.getLast30DaysHourlyStats();

            const dailyHits: number[] = [];
            const dailyBytes: number[] = [];
            
            data.forEach(d => {
                const { hits, bytes } = d.filter(h => h !== null).reduce((acc, h) => {
                    acc.hits += h.hits;
                    acc.bytes += h.bytes;
                    return acc;
                }, { hits: 0, bytes: 0 });
            
                dailyHits.push(hits);
                dailyBytes.push(bytes);
            });
            
            const hourlyData = data.at(0) || [];
            const hourlyHits = hourlyData.map(d => d?.hits || 0);
            const hourlyBytes = hourlyData.map(d => d?.bytes || 0);
            
            res.status(200).json({
                daily: [dailyHits, dailyBytes],
                hourly: [hourlyHits, hourlyBytes],
                rejected: RateLimiter.rejectedRequest.getTodayStats() || [],
                today: inst.server.centerStats.today(),
                onlines: inst.clusters.filter(c => c.isOnline).length,
                sources: inst.server.sources.length,
                totalFiles: inst.files.length,
                totalSize: inst.files.reduce((acc, f) => acc + f.size, 0),
                startTime: inst.server.startAt.getTime()
            });            
        });

        inst.app.get("/api/stats/source", (req, res) => {
            res.json(inst.server.sources);
        });

        inst.app.get("/api/stats/yesterday", (req, res) => {
            res.json({
                hits: inst.server.centerStats.getLast30DaysHourlyStats().at(2)?.map(d => d.hits || 0),
                bytes : inst.server.centerStats.getLast30DaysHourlyStats().at(2)?.map(d => d.bytes || 0),
                total: {
                    hits: inst.server.centerStats.getLast30DaysHourlyStats().at(2)?.reduce((acc, d) => acc + d.hits, 0),
                    bytes: inst.server.centerStats.getLast30DaysHourlyStats().at(2)?.reduce((acc, d) => acc + d.bytes, 0)
                },
                rejected: RateLimiter.rejectedRequest.getLast30DaysHourlyStats().at(2),
                rank: inst.stats.sort((a, b) => ((b.getLast30DaysStats().at(2)?.bytes || 0) - (a.getLast30DaysStats().at(2)?.bytes || 0))).map((s, index) => {
                    const cluster = inst.clusters.find(c => c.clusterId === s.id);
                    if (!cluster) return null;
                    const user = inst.server.db.getEntity(UserEntity, cluster.owner);
                    return {
                        rank: index + 1,
                        clusterId: cluster.clusterId,
                        name: cluster.clusterName,
                        owner: user?.username,
                        hits: s.getLast30DaysStats().at(2)?.hits || 0,
                        bytes: s.getLast30DaysStats().at(2)?.bytes || 0,
                        fullsize: cluster.shards >= FileList.SHARD_COUNT,
                        isMasterStats: cluster.masterStatsMode,
                        isProxy: cluster.isProxyCluster
                    }
                })
            });
        });
    }
}