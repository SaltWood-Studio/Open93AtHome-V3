import { ClusterEntity } from "../database/Cluster.js";
import { StatsStorage } from "../statistics/ClusterStats.js";
import { Utilities } from "../Utilities.js";
import { ApiFactory } from "./ApiFactory.js";

export class ApiClusters {
    public static register(inst: ApiFactory) {
        inst.app.get("/api/clusters", async (req, res) => { res.json(inst.clusters.map(cluster => cluster.getJson(true, true))) });
        inst.app.get("/api/clusters/:id", async (req, res) => {
            const cluster = inst.clusters.find(cluster => cluster.clusterId === req.params.id);
            if (cluster) {
                res.json(cluster.getJson(true, true));
            } else {
                res.status(404).json({ error: "Cluster not found" });
            }
        });

        inst.app.post("/api/clusters", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const name = String(req.body.name || "");
            const bandwidth = Number(req.body.bandwidth || 0);
            if (Number.isNaN(bandwidth) || bandwidth <= 10 || bandwidth > 500) {
                res.status(400).json({ error: "Invalid bandwidth" });
            }
            if (name.length < 1 || name.length > 20 || name === "") {
                res.status(400).json({ error: "Invalid name" });
            }

            let cluster = new ClusterEntity();
            cluster.clusterId = Utilities.generateRandomString(24);
            cluster.clusterSecret = Utilities.generateRandomString(32);
            cluster.clusterName = name;
            cluster.bandwidth = bandwidth;
            cluster.port = 0;
            cluster.owner = 0;
            cluster.isOnline = false;
            cluster.downReason = "null";
            cluster.createdAt = Math.floor(Date.now() / 1000);
            inst.db.insert(cluster);
            inst.server.stats.push(new StatsStorage(cluster.clusterId));
            inst.clusters.push(cluster);
            res.json(cluster.getJson(false, false));
        });

        inst.app.delete("/api/clusters/:id", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const cluster = inst.clusters.find(cluster => cluster.clusterId === req.params.id);
            if (!cluster) {
                res.status(404).json({ error: "Cluster not found" });
                return;
            }
            inst.db.remove<ClusterEntity>(ClusterEntity, cluster);
            inst.clusters = inst.clusters.filter(c => c.clusterId !== cluster.clusterId);
            res.status(200).json({ success: true });
        });

        inst.app.put("/api/clusters/:id", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const clusterId = req.query.clusterId as string || null;
            const clusterName = req.body.clusterName as string || null;
            const bandwidth = Number(req.body.bandwidth) || null;
            const sponsor = req.body.sponsor as string || null;
            const sponsorUrl = req.body.sponsorUrl as string || null;
            const isProxy = Boolean(req.body.isProxy) || false;
            const isMasterStats = Boolean(req.body.isMasterStats) || false;

            const cluster = inst.clusters.find(c => c.clusterId === clusterId);
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

            cluster.isProxyCluster = isProxy;
            cluster.masterStatsMode = isMasterStats;

            inst.db.update(cluster);
            res.json(cluster.getJson(true, false));
        });

        inst.app.post("/api/clusters/:id/reset_secret", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const cluster = inst.clusters.find(cluster => cluster.clusterId === req.params.id);
            if (!cluster) {
                res.status(404).json({ error: "Cluster not found" });
                return;
            }
            cluster.clusterSecret = Utilities.generateRandomString(32);
            inst.db.update(cluster);
            res.json({ success: true, secret: cluster.clusterSecret });
        });

        inst.app.post("/api/clusters/:id/kick", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const cluster = inst.clusters.find(cluster => cluster.clusterId === req.params.id);
            if (!cluster) {
                res.status(404).json({ error: "Cluster not found" });
                return;
            }
            cluster.doOffline("Kicked by admin");
            res.json({ success: true });
        });

        inst.app.post("/api/clusters/:id/ban", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const banned = Boolean(req.body.banned);
            const cluster = inst.clusters.find(cluster => cluster.clusterId === req.params.id);
            if (!cluster) {
                res.status(404).json({ error: "Cluster not found" });
                return;
            }
            cluster.isBanned = banned;
            inst.db.update(cluster);
            res.json({ success: true });
        });

        inst.app.get("/api/clusters/:id/shards", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const cluster = inst.clusters.find(c => c.clusterId === req.params.id);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            res.status(200).json({ shards: cluster.shards });
        });
        inst.app.put("/api/clusters/:id/shards", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const cluster = inst.clusters.find(c => c.clusterId === req.query.clusterId);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            // 判断 shards 是不是在 int 范围内
            const shards = Number(req.body.shards);
            if (shards < 0 || shards > 1000) {
                res.status(400).send({
                    message: "Shards must be between 0 and 1000"
                });
                return;
            }
            cluster.shards = shards;
            inst.db.update(cluster);
            res.setHeader('Content-Type', 'application/json');
            res.status(200).json(cluster.getJson(true, false));
        });
    }
}