import { Table } from '../sqlite';
import { StatsStorage } from '../statistics/cluster-stats';

@Table('clusters', `
    clusterId TEXT PRIMARY KEY,
    clusterSecret TEXT,
    endpoint TEXT,
    port INTEGER,
    owner INTEGER,
    downReason TEXT,
    clusterName TEXT,
    bandwidth INTEGER,
    traffic INTEGER,
    hits INTEGER,
    isBanned BOOLEAN
`)
export class ClusterEntity {
    public clusterId: string = '';

    public clusterSecret: string = '';

    public endpoint: string = '';

    public port: number = 80;

    public owner: number = 80;

    public downReason: string = '';

    public clusterName: string = '';

    public bandwidth: number = 30;

    public measureBandwidth: number = -1;

    public traffic: number = 0;

    public pendingTraffic: number = 0;

    public hits: number = 0;

    public pendingHits: number = 0;

    public isOnline: boolean = false;

    public isBanned: boolean = false;
}