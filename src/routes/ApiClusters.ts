import { Config } from "../Config.js";
import { ClusterEntity } from "../database/Cluster.js";
import { UserEntity } from "../database/User.js";
import { StatsStorage } from "../statistics/ClusterStats.js";
import { Utilities } from "../Utilities.js";
import { ApiFactory } from "./ApiFactory.js";

export class ApiClusters {
    public static register(inst: ApiFactory) {
        inst.app.get("/api/clusters", async (req, res) => {
            // 仅显示特定天数内有活动的节点
            // 先把节点按照在线和离线分成两部分，然后各自按照 traffic 从大到小排序，最后返回 JSON 字符串
            const clusters = Config.instance.data.shownDays > 0
                ? inst.clusters.filter(c => c.lastSeen > Utilities.getDate(-Config.instance.data.shownDays, "day").getTime())
                : inst.clusters;
            const onlineClusters = clusters.filter(c => c.isOnline);
            const offlineClusters = clusters.filter(c => !c.isOnline);
        
            const onlineClustersSorted = onlineClusters
                .sort((a, b) => {
                    const aStat = inst.stats.find(s => s.id === a.clusterId)?.getTodayStats();
                    const bStat = inst.stats.find(s => s.id === b.clusterId)?.getTodayStats();
                    if (aStat && bStat) {
                        return bStat.bytes - aStat.bytes;
                    } else {
                        return 0;
                    }
                })
                .map(c => c.getJson(true, true));
        
            const offlineClustersSorted = offlineClusters
                .sort((a, b) => {
                    const aStat = inst.stats.find(s => s.id === a.clusterId)?.getTodayStats();
                    const bStat = inst.stats.find(s => s.id === b.clusterId)?.getTodayStats();
                    if (aStat && bStat) {
                        return bStat.bytes - aStat.bytes;
                    } else {
                        return 0;
                    }
                })
                .map(c => c.getJson(true, true));
        
            // 添加 ownerName 并返回 JSON 响应
            const result = onlineClustersSorted.concat(offlineClustersSorted).map(c => {
                const stat = inst.stats.find(s => s.id === c.clusterId)?.getTodayStats();
                return {
                    ...c,
                    ownerName: inst.db.getEntity<UserEntity>(UserEntity, c.owner)?.username || '',
                    hits: stat?.hits || 0,
                    bytes: stat?.bytes || 0
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
        inst.app.get("/api/clusters/:id", async (req, res) => {
            const cluster = inst.clusters.find(cluster => cluster.clusterId === req.params.id);
            if (!cluster) {
                res.status(404).json({ error: "Cluster not found" });
                return;
            }
            const stat = inst.stats.find(s => s.id === cluster.clusterId)?.getTodayStats();
            res.json({
                ...cluster.getJson(true, true),
                ownerName: inst.db.getEntity<UserEntity>(UserEntity, cluster.owner)?.username || '',
                hits: stat?.hits || 0,
                bytes: stat?.bytes || 0
            });
        });

        inst.app.post("/api/clusters", async (req, res) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            const name = String(req.body.name || "");
            const bandwidth = Number(req.body.bandwidth || 0);
            if (Number.isNaN(bandwidth) || bandwidth <= 10 || bandwidth > 500) {
                res.status(400).json({ error: "Invalid bandwidth" });
                return;
            }
            if (name.length < 1 || name.length > 20 || name === "") {
                res.status(400).json({ error: "Invalid name" });
                return;
            }
            if (!Utilities.checkName(name)) {
                res.status(400).json({ error: "Name cannot contain special characters" });
                return;
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
            cluster.createdAt = Utilities.getTimestamp();
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
            const clusterId = req.params.id;
            const clusterName = req.body.name as string || null;
            const bandwidth = Number(req.body.bandwidth) || null;
            const sponsor = req.body.sponsor as string || null;
            const sponsorUrl = req.body.sponsorUrl as string || null;
            const sponsorBanner = req.body.sponsorBanner as string || null;
            const isProxy = Boolean(req.body.isProxy) || false;
            const isMasterStats = Boolean(req.body.isMasterStats) || false;
            const noWarden = Boolean(req.body.noWarden) || false;

            if (!Utilities.checkName(clusterName) || !Utilities.checkName(sponsor) || !Utilities.checkName(sponsorUrl) || !Utilities.checkName(sponsorBanner)) {
                res.status(400).json({ error: "Cannot contain special characters" });
                return;
            }

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
            if (sponsorBanner) cluster.sponsorBanner = sponsorBanner;

            cluster.isProxyCluster = isProxy;
            cluster.masterStatsMode = isMasterStats;
            cluster.noWardenMode = noWarden;

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
            const cluster = inst.clusters.find(c => c.clusterId === req.params.id);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            // 判断 shards 是不是在 int 范围内
            const shards = Number(req.body.shards);
            if (Number.isNaN(shards)) {
                res.status(400).send({
                    message: "Not a Number"
                });
            }
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