import { Socket } from 'socket.io';
import { Ignore, Table, PrimaryKey } from '../SQLiteHelper.js';
import { StatsStorage } from '../statistics/ClusterStats.js';
import { Utilities } from '../Utilities.js';
import { File } from './File.js';
import { clear } from 'console';
import { Config } from '../Config.js';
import { FileList } from '../FileList.js';

@Table('clusters', `
    clusterId TEXT PRIMARY KEY UNIQUE,
    clusterSecret TEXT,
    endpoint TEXT,
    port INTEGER,
    owner INTEGER,
    downReason TEXT,
    clusterName TEXT,
    bandwidth INTEGER,
    banned INTEGER,
    createdAt INTEGER,
    sponsor TEXT,
    sponsorUrl TEXT,
    version TEXT,
    downTime INTEGER,
    shards INTEGER, 
    isProxy INTEGER,
    isMasterStats INTEGER
`)
@PrimaryKey('clusterId')
export class ClusterEntity {
    public clusterId: string = '';

    public clusterSecret: string = '';

    public endpoint: string = '';

    public port: number = 80;

    public owner: number = 80;

    public downReason: string = '';

    public clusterName: string = '';

    public bandwidth: number = 30;

    @Ignore()
    public measureBandwidth: number = -1;

    @Ignore()
    public pendingTraffic: number = 0;

    @Ignore()
    public pendingHits: number = 0;

    @Ignore()
    public isOnline: boolean = false;

    private banned: number = 0;
    public get isBanned(): boolean { return Boolean(this.banned); }
    public set isBanned(value: boolean) { this.banned = Number(value); }

    public createdAt: number = 0;

    public sponsor: string = '';

    public sponsorUrl: string = '';

    public version: string = '';

    public downTime: number = 0;

    public shards: number = 1000;

    @Ignore()
    public enableHistory: Date[] = [];

    @Ignore()
    private interval: NodeJS.Timeout | null = null;

    private isProxy: number = 0;

    public get isProxyCluster(): boolean { return Boolean(this.isProxy); }
    public set isProxyCluster(value: boolean) { this.isProxy = Number(value); }

    private isMasterStats: number = 0;

    public get masterStatsMode(): boolean { return Boolean(this.isMasterStats); }
    public set masterStatsMode(value: boolean) { this.isMasterStats = Number(value); }

    public doOffline(reason: string = "Unspecfied"): void {
        this.isOnline = false;
        this.downReason = reason;
        this.downTime = Math.floor(Date.now() / 1000);
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
    }

    public doOnline(files: File[], io: Socket): void {
        this.isOnline = true;
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
        if (!Config.instance.noWarden) {
            this.interval = setInterval(() => {
                const file = Utilities.getRandomElement(files);
                if (file) {
                    Utilities.checkSpecfiedFiles([file], this, -5)
                    .then(result => {
                        if (result) {
                            this.doOffline(`Warden failed: ${file.hash}, result: ${result}`);
                            io.emit('warden-error', { message: this.downReason, file: file })
                        }
                    })
                    .catch(error => {
                        this.doOffline(`Warden failed: ${file.hash}, error: ${error}`);
                        io.emit('warden-error', { message: this.downReason, file: file, error: error })
                    });
                }
            }, 1000 * 60 * 5);
        }
    }

    public getJson(removeSecret: boolean = false, removeSensitive: boolean = false): any {
        const removeSensitiveInfo = ({ clusterSecret, endpoint, measureBandwidth, port, downReason, shards, ...rest }: any) => rest;
        const removeSecretInfo = ({ clusterSecret, ...rest }: any) => rest;
        const optimizeJsonObject = ({ interval, banned, isProxy, isMasterStats, enableHistory, ...rest }: ClusterEntity) => {
            return {
                ...rest,
                fullsize: this.shards >= 1000,
                isMasterStats: Boolean(isMasterStats),
                isProxy: Boolean(isProxy),
                isBanned: Boolean(banned),
            }
        };
        let json: any = optimizeJsonObject(this);
        if (removeSensitive) json = removeSensitiveInfo(json);
        if (removeSecret) json = removeSecretInfo(json);
        return json;
    } 
}