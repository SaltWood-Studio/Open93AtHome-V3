import { Ignore, Table, PrimaryKey } from '../sqlite';
import { StatsStorage } from '../statistics/cluster-stats';
import { Utilities } from '../utilities';
import { File } from './file';

@Table('clusters', `
    clusterId TEXT PRIMARY KEY UNIQUE,
    clusterSecret TEXT,
    endpoint TEXT,
    port INTEGER,
    owner INTEGER,
    downReason TEXT,
    clusterName TEXT,
    bandwidth INTEGER,
    traffic INTEGER,
    hits INTEGER,
    isBanned INTEGER,
    createdAt INTEGER,
    sponsor TEXT,
    sponsorUrl TEXT,
    version TEXT,
    downTime INTEGER
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

    public traffic: number = 0;

    @Ignore()
    public pendingTraffic: number = 0;

    public hits: number = 0;

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

    private interval: NodeJS.Timeout | null = null;

    public doOffline(reason: string = "Unspecfied"): void {
        this.isOnline = false;
        this.downReason = reason;
        this.downTime = Date.now();
        this.interval && clearInterval(this.interval);
    }

    public doOnline(files: File[]): void {
        this.isOnline = true;
        this.interval = setInterval(() => {
            const file = Utilities.getRandomElement(files);
            if (file) {
                Utilities.checkSpecfiedFiles([file], this, -5)
                .then(result => {
                    if (!result) {
                        this.doOffline(`Warden failed: ${file.hash}, ${result}`);
                    }
                })
                .catch(error => {
                    this.doOffline(`Warden failed: ${file.hash}, ${error}`);
                });
            }
        });
    }

    public getJson(removeSecret: boolean = false, removeSensitive: boolean = false): any {
        const convertBanned = ({ isBanned, ...rest }: ClusterEntity) => {
            return {
                isBanned: Boolean(isBanned),
                ...rest
            };
        };
        const removeSensitiveInfo = ({ clusterSecret, endpoint, bandwidth, measureBandwidth, port, downReason, ...rest }: {clusterSecret: string, endpoint: string, bandwidth: number, measureBandwidth: number, port: number, downReason: string, [key: string]: any}) => rest;
        const removeSecretInfo = ({ clusterSecret, ...rest }: {clusterSecret: string, [key: string]: any}) => rest;
        let json: any = convertBanned(this);
        if (removeSensitive) json = removeSensitiveInfo(json);
        if (removeSecret) json = removeSecretInfo(json);
        return json;
    } 
}