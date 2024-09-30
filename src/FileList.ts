import { ClusterEntity } from './database/Cluster.js';
import { File } from './database/File.js';
import crc32 from 'crc-32';
import { Utilities } from './Utilities.js';

export class FileList {
    // 不能大于 number 的安全范围 MAX_SAFE_INTEGER = 2 ^ 53 - 1
    public static readonly SHARD_COUNT = 32; // 最大 53

    private _files: File[] = [];
    private _clusters: ClusterEntity[] = [];
    private _shards: File[][] = [];

    public constructor(files: File[] | undefined = undefined, clusters: ClusterEntity[] | undefined = undefined) {
        this._files = files ? files : [];
        this._clusters = clusters? clusters : [];
        this.notifyUpdateShards();
    }

    public notifyUpdateShards(): void {
        this._shards = FileList.splitIntoShards(this._files, FileList.SHARD_COUNT);
        console.log(`File shards updated: ${this._shards.map(s => s.length)}`);
        for (const cluster of this._clusters) {
            const availableShards = Utilities.intToBooleans(cluster.availShards, FileList.SHARD_COUNT);
            console.log(`Cluster ${cluster.clusterId}, shards: ${cluster.availShards}, available shards: ${availableShards.filter(b => b).length}`);
        }
    }

    public set files(files: File[]) {
        this._files = files;
        this.notifyUpdateShards();
    }

    public get files(): File[] {
        return this._files;
    }

    public set clusters(clusters: ClusterEntity[]) {
        this._clusters = clusters;
    }

    public get clusters(): ClusterEntity[] {
        return this._clusters;
    }

    public get shards(): File[][] {
        return this._shards;
    }

    public exists(type: "path" | "hash", value: string): boolean {
        return this.getFiles(type, value).length > 0;
    }

    public getFile(type: "path" | "hash", value: string): File | undefined {
        let index: number;
        if (type === "path") index = FileList.getShardIndex(value, FileList.SHARD_COUNT);
        else if (type === "hash") return this._files.find(file => file.hash === value);
        else throw new Error("Invalid type");

        return this._shards[index].find((file) => file.path === value);
    }

    public getFiles(type: "path" | "hash", value: string): File[] {
        let index: number;
        if (type === "path") index = FileList.getShardIndex(value, FileList.SHARD_COUNT);
        else if (type === "hash") return this.getFiles("path", this._files.find(file => file.hash === value)?.path || "");
        else throw new Error("Invalid type");

        return this._shards[index].filter((file) => file.path === value);
    }

    public getAvailableFiles(cluster: ClusterEntity): File[] {
        const availableShards = Utilities.intToBooleans(cluster.availShards, FileList.SHARD_COUNT);

        return this._shards.filter((_, index) => availableShards[index]).flat();
    }

    public getAvailableClusters(file: File, clusters: ClusterEntity[] | undefined = undefined): ClusterEntity[] {
        const availableClusters: ClusterEntity[] = [];
        const values = clusters? clusters : this._clusters;

        for (const cluster of values.filter(c => c.isOnline && !(c.isBanned))) {
            if (FileList.availableInCluster(file, cluster)) {
                availableClusters.push(cluster);
            }
        }

        return availableClusters;
    }

    public randomAvailableCluster(file: File, clusters: ClusterEntity[] | undefined = undefined): ClusterEntity | null {
        const availableClusters = this.getAvailableClusters(file, clusters);
        return Utilities.getWeightedRandomElement(availableClusters, c => c.measureBandwidth || 0);
    }

    public static availableInCluster(file: File, cluster: ClusterEntity): boolean {
        const index = FileList.getShardIndex(file.path, FileList.SHARD_COUNT);
        return (cluster.availShards & (1 << index)) !== 0;
    }

    // 计算对象的分片索引
    public static getShardIndex(value: string, totalShards: number): number {
        const crcValue = Math.abs(crc32.str(value));
        return crcValue % totalShards;
    }

    // 将对象分配到不同的分片中
    public static splitIntoShards(objects: File[], totalShards: number): File[][] {
        const shards: File[][] = Array.from({ length: totalShards }, () => []);
        
        objects.forEach((obj) => {
            const shardIndex = FileList.getShardIndex(obj.path, totalShards);
            shards[shardIndex].push(obj);
        });

        return shards;
    }
}