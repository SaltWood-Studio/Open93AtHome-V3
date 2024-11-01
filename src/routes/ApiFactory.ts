import { ACME } from "../certificate-manager/ACME.js";
import { DnsManager } from "../certificate-manager/DnsManager.js";
import { ClusterEntity } from "../database/Cluster.js";
import { UserEntity } from "../database/User.js";
import { FileList } from "../FileList.js";
import { Server } from "../Server.js";
import { SQLiteHelper } from "../SQLiteHelper.js";
import { Express } from "express";
import { ApiClusters } from "./ApiClusters.js";
import { StatsStorage } from "../statistics/ClusterStats.js";
import { File } from "../database/File.js";
import { Got } from "got";
import { ApiAdmin } from "./ApiAdmin.js";
import { ApiUser } from "./ApiUser.js";
import { ApiAuth } from "./ApiAuth.js";

export class ApiFactory {
    public fileList: FileList;
    public server: Server;
    public db: SQLiteHelper;
    public dns: DnsManager | null;
    public acme: ACME | null;
    public app: Express;

    public get got(): Got {
        return this.server.got;
    }
    public get files(): File[] {
        return this.fileList.files;
    }
    public get clusters(): ClusterEntity[] {
        return this.fileList.clusters;
    }
    public set clusters(value: ClusterEntity[]) {
        this.fileList.clusters = value;
    }
    public get users(): UserEntity[] {
        return this.db.getEntities<UserEntity>(UserEntity);
    }
    public get stats(): StatsStorage[] {
        return this.server.stats;
    }
    
    constructor(server: Server, fileList: FileList, db: SQLiteHelper, dns: DnsManager | null, acme: ACME | null, app: Express) {
        this.server = server;
        this.fileList = fileList;
        this.db = db;
        this.dns = dns;
        this.acme = acme;
        this.app = app;
    }

    public factory(): void {
        ApiClusters.register(this);
        ApiAdmin.register(this);
        ApiUser.register(this);
        ApiAuth.register(this);
    }
}