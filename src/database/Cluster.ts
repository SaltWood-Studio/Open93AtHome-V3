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
    isBanned INTEGER,
    createdAt INTEGER,
    sponsor TEXT,
    sponsorUrl TEXT,
    version TEXT,
    downTime INTEGER,
    availShards INTEGER
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

    public isBanned: number = 0;

    public createdAt: number = 0;

    public sponsor: string = '';

    public sponsorUrl: string = '';

    public version: string = '';

    public downTime: number = 0;

    public availShards: number = -1;

    @Ignore()
    public enableHistory: Date[] = [];

    @Ignore()
    private interval: NodeJS.Timeout | null = null;

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
        const removeSensitiveInfo = ({ clusterSecret, endpoint, measureBandwidth, port, downReason, availShards, ...rest }: any) => rest;
        const removeSecretInfo = ({ clusterSecret, ...rest }: any) => rest;
        const optimizeJsonObject = ({ interval, isBanned, enableHistory, ...rest }: ClusterEntity) => {
            return {
                ...rest,
                isBanned: Boolean(this.isBanned),
                fullsize: Utilities.intToBooleans(this.availShards, FileList.SHARD_COUNT).every(Boolean)
            }
        };
        let json: any = optimizeJsonObject(this);
        if (removeSensitive) json = removeSensitiveInfo(json);
        if (removeSecret) json = removeSecretInfo(json);
        return json;
    } 
}