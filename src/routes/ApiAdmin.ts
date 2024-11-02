import { Config } from "../Config.js";
import { ClusterEntity } from "../database/Cluster.js";
import { UserEntity } from "../database/User.js";
import JwtHelper from "../JwtHelper.js";
import { Utilities } from "../Utilities.js";
import { ApiFactory } from "./ApiFactory.js";
import { NextFunction, Request, Response } from "express";

export class ApiAdmin {
    public static register(inst: ApiFactory) {
        const verifyAdminMiddleware = (req: Request, res: Response, next: NextFunction) => {
            if (!Utilities.verifyAdmin(req, res, inst.db)) return;
            next();
        };

        inst.app.use("/api/admin", verifyAdminMiddleware);

        inst.app.post("/api/admin/sudo", async (req, res) => {
            const user = inst.db.getEntity<UserEntity>(UserEntity, (JwtHelper.instance.verifyToken(req.cookies.adminToken, 'admin') as { userId: number }).userId);
            if (!user) {
                res.status(401).send();
                return;
            }
            const id = Number(req.body.id)
            const targetUser = inst.db.getEntity<UserEntity>(UserEntity, id);
            if (!targetUser) {
                res.status(404).send();
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

        inst.app.post("/api/admin/update", async (req, res) => {
            if (inst.server.isUpdating) {
                res.status(409).send({
                    success: false,
                    message: "Files are currently updating, please try again later."
                });
                return;
            }
            inst.server.updateFiles();
            res.status(200).json({
                success: true
            });
        });

        inst.app.get("/api/admin/all_users", async (req, res) => { res.json(inst.db.getEntities<UserEntity>(UserEntity)) });
        inst.app.get("/api/admin/all_clusters", async (req, res) => {
            const result = inst.db.getEntities<ClusterEntity>(ClusterEntity).map(c => c.getJson(true, false)).map(c => {
                const ignoredFields = (c as any).ignoredFields || [];
                const obj = c as Record<string, any>;
                const keys = Object.keys(c).filter(k => !ignoredFields.includes(k));
                const values = keys.map(k => obj[k]);
                
                const result = keys.reduce((acc, key) => {
                    acc[key] = obj[key];
                    return acc;
                }, {} as Record<string, any>);

                return result;
            });
            res.json(result);
        });
    }
}