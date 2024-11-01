import { Config } from "../Config.js";
import { UserEntity } from "../database/User.js";
import JwtHelper from "../JwtHelper.js";
import { Utilities } from "../Utilities.js";
import { ApiFactory } from "./ApiFactory.js";
import { NextFunction, Request, Response } from "express";

export class ApiUser {
    public static register(inst: ApiFactory) {
        inst.app.get("/api/user/me", async (req, res) => {
            if (!Utilities.verifyUser(req, res, inst.db)) return;
            const token = req.cookies.token;
            const user = inst.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send({ message: 'User not found' });
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

        inst.app.post("/api/user/clusters/bind", async (req, res) => {
            if (!Utilities.verifyUser(req, res, inst.db)) return;
            const token = req.cookies.token;
            const user = inst.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send({ message: 'User not found' });
                return;
            }
            const body = req.body as { clusterId: string, clusterSecret: string };
            res.setHeader('Content-Type', 'application/json');
            const cluster = inst.clusters.find(c => c.clusterId === body.clusterId);
            if (!cluster) {
                res.status(404).send({ message: 'Cluster not found' })
                return;
            }
            if (cluster.owner!== 0) {
                res.status(403).send({ message: 'Cluster already bound' });
                return;
            }
            if (cluster.clusterSecret !== body.clusterSecret) {
                res.status(403).send({ message: 'Invalid cluster secret' });
                return;
            }
            cluster.owner = user.id;
            inst.db.update(cluster);
            res.status(200).json(cluster.getJson(true, false));
        });

        inst.app.post("/api/user/clusters/unbind", async (req, res) => {
            if (!Utilities.verifyUser(req, res, inst.db)) return;
            const token = req.cookies.token;
            const user = inst.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send({ message: 'User not found' });
                return;
            }
            const body = req.body as { clusterId: string };
            res.setHeader('Content-Type', 'application/json');
            const cluster = inst.clusters.find(c => c.clusterId === body.clusterId && Number(c.owner) === user.id);
            if (!cluster) {
                res.status(404).send({ message: 'Cluster not found or not bound to this user' });
                return;
            }
            cluster.owner = 0;
            inst.db.update(cluster);
            res.status(200).json(cluster.getJson(true, false));
        });

        inst.app.get("/api/user/clusters", async (req, res) => {
            if (!Utilities.verifyUser(req, res, inst.db)) return;
            const token = req.cookies.token;
            const user = inst.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send("User not found.");
                return;
            }
            res.setHeader('Content-Type', 'application/json');
            const clusters = inst.clusters.filter(c => c.owner === user.id);
            res.status(200).json(clusters.map(c => c.getJson(true, false)));
        });

        inst.app.get("/api/user/clusters/:id", async (req, res) => {
            if (!Utilities.verifyUser(req, res, inst.db)) return;
            const clusterId = req.params.id;
            const token = req.cookies.token;
            const user = inst.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send("User not found.");
                return;
            }
            res.setHeader('Content-Type', 'application/json');
            const cluster = inst.clusters.find(c => c.clusterId === clusterId && c.owner === user.id);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            res.status(200).json(cluster.getJson(true, false));
        });

        inst.app.post("/api/user/clusters/:id", async (req, res) => {
            if (!Utilities.verifyUser(req, res, inst.db)) return;
            const token = req.cookies.token;
            const user = inst.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send("User not found.");
                return;
            }
            const clusterId = req.params.id;
            const cluster = inst.clusters.find(c => c.clusterId === clusterId && c.owner === user.id);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            const clusterName = req.body.clusterName as string || null;
            const bandwidth = Number(req.body.bandwidth) || 0;
            const sponsor = req.body.sponsor as string || null;
            const sponsorUrl = req.body.sponsorUrl as string || null;

            if (clusterName) cluster.clusterName = clusterName;
            if (bandwidth) {
                if (Number.isNaN(bandwidth) || bandwidth < 10 || bandwidth > 500) {
                    res.status(400).send({ message: 'Invalid bandwidth' });
                    return;
                }
            }
            if (sponsor) cluster.sponsor = sponsor;
            if (sponsorUrl) cluster.sponsorUrl = sponsorUrl;

            inst.db.update(cluster);
            res.status(200).json(cluster.getJson(true, false));
        });

        inst.app.post("/api/user/clusters/:id/reset_secret", async (req, res) => {
            const token = req.cookies.token;
            if (!token) {
                res.status(401).send(); // 未登录
                return;
            }
            const user = inst.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(token, 'user') as { userId: number }).userId);
            if (!user) {
                res.status(404).send(); // 用户不存在
                return;
            }
            res.setHeader('Content-Type', 'application/json');
            const cluster = inst.clusters.find(c => c.clusterId === req.query.clusterId && c.owner === user.id);
            if (!cluster) {
                res.status(404).send(); // 集群不存在
                return;
            }
            const secret = Utilities.generateRandomString(32);
            cluster.clusterSecret = secret;
            inst.db.update(cluster);
            res.status(200).json({
                success: true,
                secret: secret
            });
        });
    }
}