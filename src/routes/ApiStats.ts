import RateLimiter from "../RateLimiter.js";
import { ApiFactory } from "./ApiFactory.js";

export class ApiStats {
    public static register(inst: ApiFactory) {
        inst.app.get("/api/stats/cluster/:id", (req, res) => {
            res.setHeader('Content-Type', 'application/json');
            const clusterId = req.query.clusterId as string;
            const cluster = inst.clusters.find(c => c.clusterId === clusterId);
            if (cluster) {
                const stats = inst.stats.find(s => s.id === clusterId);
                if (stats) {
                    res.status(200).json(stats.getLast30DaysStats());
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
            const daily = data.map(d => {
                let hits = 0;
                let bytes = 0;
                d.filter(h => h !== null).forEach(h => {
                    hits += h.hits;
                    bytes += h.bytes;
                });
                return { hits, bytes };
            });

            res.status(200).json({
                daily,
                hourly: data.at(0)?.map(hour => ([hour.hits, hour.bytes])) || [],
                rejected: RateLimiter.rejectedRequest.getLast30DaysHourlyStats().at(0)?.map(hour => hour.hits) || [],
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
    }
}