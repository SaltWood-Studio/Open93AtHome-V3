import { ClusterEntity } from './database/Cluster.js';
import { File } from './database/File.js';
import crc32 from 'crc-32';
import { Utilities } from './Utilities.js';

export class FileList {
    public static readonly SHARD_COUNT = 64;

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
            const availableShards = Utilities.bigIntToBooleans(cluster.availShards, FileList.SHARD_COUNT);
            console.log(`Cluster ${cluster.clusterId}, available shards: ${availableShards.filter(b => b).length}`);
        }
    }

    public set files(files: File[]) {
        this._files = files;
        this.notifyUpdateShards();
    }

    public get files(): File[] {
        return this._files;
    }

    public get shards(): File[][] {
        return this._shards;
    }

    public exists(type: "path" | "hash", value: string): boolean {
        return this.getFiles(type, value).length > 0;
    }

    public getFiles(type: "path" | "hash", value: string): File[] {
        let index: number;
        if (type === "path") index = FileList.getShardIndex(value, FileList.SHARD_COUNT);
        else if (type === "hash") index = FileList.getShardIndex(value, FileList.SHARD_COUNT);
        else throw new Error("Invalid type");

        return this._shards[index].filter((file) => {
            if (type === "path") return file.path === value;
            else if (type === "hash") return file.hash === value;
            else throw new Error("Invalid type");
        });
    }

    public getAvailableFiles(cluster: ClusterEntity): File[] {
        const availableShards = Utilities.bigIntToBooleans(cluster.availShards, FileList.SHARD_COUNT);

        return this._shards.filter((_, index) => availableShards[index]).flat();
    }

    public getAvailableClusters(file: File, clusters: ClusterEntity[] | undefined = undefined): ClusterEntity[] {
        const availableClusters: ClusterEntity[] = [];
        if (!clusters) clusters = this._clusters;
        clusters.filter(cluster => cluster.isOnline).forEach((cluster) => {
            if (Utilities.bigIntToBooleans(cluster.availShards, FileList.SHARD_COUNT)[FileList.getShardIndex(file.path, FileList.SHARD_COUNT)]) {
                availableClusters.push(cluster);
            }
        });

        return availableClusters;
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