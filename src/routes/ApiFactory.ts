import { ACME } from "../certificate-manager/ACME.js";
import { DnsManager } from "../certificate-manager/DnsManager.js";
import { ClusterEntity } from "../database/Cluster.js";
import { UserEntity } from "../database/User.js";
import { FileList } from "../FileList.js";
import { Server } from "../Server.js";
import { SQLiteHelper } from "../SQLiteHelper.js";
import { Express } from "express";
import { ApiClusters } from "./ApiClusters.js";

export class ApiFactory {
    public fileList: FileList;
    public server: Server;
    public db: SQLiteHelper;
    public dns: DnsManager | null;
    public acme: ACME | null;
    public app: Express;

    public get got() {
        return this.server.got;
    }
    public get files() {
        return this.fileList.files;
    }
    public get clusters() {
        return this.fileList.clusters;
    }
    public set clusters(value: ClusterEntity[]) {
        this.fileList.clusters = value;
    }
    public get users() {
        return this.db.getEntities<UserEntity>(UserEntity);
    }
    
    constructor(server: Server, fileList: FileList, db: SQLiteHelper, dns: DnsManager | null, acme: ACME | null, app: Express) {
        this.server = server;
        this.fileList = fileList;
        this.db = db;
        this.dns = dns;
        this.acme = acme;
        this.app = app;
    }

    public factory() {
        ApiClusters.register(this);
    }
}