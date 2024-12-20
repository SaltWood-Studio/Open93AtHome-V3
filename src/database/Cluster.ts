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
    sponsorBanner TEXT,
    version TEXT,
    downTime INTEGER,
    lastSeen INTEGER,
    shards INTEGER, 
    isProxy INTEGER,
    isMasterStats INTEGER,
    noWarden INTEGER
`)
@PrimaryKey('clusterId')
export class ClusterEntity {
    public clusterId: string = '';

    public clusterSecret: string = '';

    public endpoint: string = '';

    public port: number = 80;

    public owner: number = 0;

    public downReason: string = '';

    public clusterName: string = '';

    public bandwidth: number = 30;

    @Ignore()
    public measureBandwidth: number = -1;

    @Ignore()
    public pendingBytes: number = 0;

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
    public sponsorBanner: string = '';

    public version: string = '';

    public downTime: number = 0;

    public lastSeen: number = 0;

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

    private noWarden: number = 0;

    public get noWardenMode(): boolean { return Boolean(this.noWarden); }
    public set noWardenMode(value: boolean) { this.noWarden = Number(value); }

    public doOffline(reason: string = "Unspecfied"): void {
        this.isOnline = false;
        this.downReason = reason;
        this.downTime = Utilities.getTimestamp();
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
    }

    public doOnline(files: File[], io: Socket, noWarden: boolean = false): void {
        this.isOnline = true;
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
        if (!noWarden) {
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
        const optimizeJsonObject = ({ interval, banned, isProxy, noWarden, isMasterStats, enableHistory, shards, ...rest }: ClusterEntity) => {
            return {
                ...rest,
                shards,
                fullsize: shards >= 1000,
                isMasterStats: Boolean(isMasterStats),
                isProxy: Boolean(isProxy),
                noWarden: Boolean(noWarden),
                isBanned: Boolean(banned),
            }
        };
        let json: any = optimizeJsonObject(this);
        if (removeSensitive) json = removeSensitiveInfo(json);
        if (removeSecret) json = removeSecretInfo(json);
        return json;
    } 
}