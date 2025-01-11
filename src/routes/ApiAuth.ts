import { Config } from "../Config.js";
import { GitHubUser } from "../database/GitHubUser.js";
import { UserEntity } from "../database/User.js";
import HttpRequest from "../HttpRequest.js";
import JwtHelper from "../JwtHelper.js";
import { Utilities } from "../Utilities.js";
import { ApiFactory } from "./ApiFactory.js";
import { NextFunction, Request, Response } from "express";

export class ApiAuth {
    public static register(inst: ApiFactory) {
        inst.app.get("/api/auth/id", (req: Request, res: Response) => {
            res.end(Config.instance.github.oAuthClientId);
        });
        inst.app.post("/api/auth/login", async (req: Request, res: Response) => {
            res.set("Content-Type", "application/json");
        
            try {
                const code = req.query.code as string || '';
        
                // 请求GitHub获取access_token
                const tokenData = await HttpRequest.request.post(`https://${Config.instance.github.url}/login/oauth/access_token`, {
                    form: {
                        code,
                        client_id: Config.instance.github.oAuthClientId,
                        client_secret: Config.instance.github.oAuthClientSecret
                    },
                    headers: {
                        'Accept': 'application/json'
                    },
                    responseType: 'json'
                }).json<{ access_token: string }>();
        
                const accessToken = tokenData.access_token;
        
                let userResponse = await HttpRequest.request.get(`https://${Config.instance.github.apiUrl}/user`, {
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
                let dbUser = inst.db.getEntity<UserEntity>(UserEntity, user.id);
                if (dbUser) {
                    inst.db.update(user.toUserWithDbEntity(dbUser));
                } else {
                    inst.db.insert<UserEntity>(user.toUserEntity());
                }
        
                // 生成JWT并设置cookie
                const token = JwtHelper.instance.issueToken({
                    userId: user.id,
                    clientId: Config.instance.github.oAuthClientId
                }, "user", 60 * 60 * 24);
        
                res.cookie('token', token, {
                    expires: Utilities.getDate(1, "day"),
                    secure: true,
                    sameSite: 'lax',
                });

                if (inst.db.getEntity<UserEntity>(UserEntity, user.id)?.isSuperUser) {
                    const adminToken = JwtHelper.instance.issueToken({
                        userId: user.id,
                        clientId: Config.instance.github.oAuthClientId
                    }, "admin", 60 * 60 * 24);
                    res.cookie('adminToken', adminToken, {
                        expires: Utilities.getDate(1, "day"),
                        secure: true,
                        sameSite: 'lax',
                    });
                }
        
                const login = inst.db.getEntity<UserEntity>(UserEntity, user.id);

                res.status(200).json(login);
            } catch (error) {
                const err = error as Error;
                console.error('Error processing GitHub OAuth:', err);
                res.status(500).json({
                    error: `${err.name}: ${err.message}`
                });
            }
        });
    }
}