import { Ignore, Table, PrimaryKey } from '../sqlite';
import { StatsStorage } from '../statistics/cluster-stats';

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

    public doOnline(): void {
        this.isOnline = true;
        this.interval = setInterval(() => {});
    }
}