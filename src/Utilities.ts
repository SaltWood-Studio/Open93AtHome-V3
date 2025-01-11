import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Request, Response } from 'express';
import JwtHelper from './JwtHelper.js';
import { File, IFileInfo } from './database/File.js';
import { compress } from '@mongodb-js/zstd';
import avsc from 'avsc';
import { exec, ExecException } from 'child_process';
import { ClusterEntity } from './database/Cluster.js';
import { SQLiteHelper } from './SQLiteHelper.js';
import { UserEntity } from './database/User.js';
import { Config } from './Config.js';
import os from 'os';
import HttpRequest from './HttpRequest.js';

export const FileListSchema = avsc.Type.forSchema({
  type: 'array',
  items: {
    name: 'files',
    type: 'record',
    fields: [
      {name: 'encodedPath', type: 'string'},
      {name: 'hash', type: 'string'},
      {name: 'size', type: 'long'},
      {name: 'lastModified', type: 'long'},
    ],
  },
});

const bannedCharacters = /[&<>\"'\r\n]/g;

export class Utilities {
    public static isRunningInDocker(): boolean {
        return process.env.IS_IN_DOCKER === 'true';
    }

    public static generateRandomString(length: number): string {
        return crypto.randomBytes(length).toString('hex').slice(0, length);
    }

    public static execCommand(command: string, cwd: string, timeout: number = 30000): Promise<void> {
        return new Promise((resolve, reject) => {
            const childProcess = exec(command, { cwd }, (error: ExecException | null, stdout: string, stderr: string) => {
                if (error) {
                    console.error(`Error updating repository ${cwd}: ${error.message}`);
                    reject(error);
                    return;
                }
                if (stderr) {
                    console.error(`Stderr for repository ${cwd}: ${stderr}`);
                    reject(new Error(stderr));
                    return;
                }
                console.log(`Repository ${cwd} updated successfully.`);
                console.log(stdout);
                resolve();
            });
    
            // 设置超时逻辑
            const timeoutId = setTimeout(() => {
                childProcess.kill();  // 强制终止子进程
                reject(new Error(`Command timed out after ${timeout} ms`));
            }, timeout);
    
            // 清理定时器
            childProcess.on('exit', () => {
                clearTimeout(timeoutId);  // 如果命令正常退出，清除超时定时器
            });
        });
    }

    // 并行处理所有仓库
    public static async updateGitRepositories(rootDir: string): Promise<void> {
        // 读取根目录下的所有子目录
        const directories = fs.readdirSync(rootDir, { withFileTypes: true })
            .filter(dirent => dirent.isDirectory()) // 只保留文件夹
            .map(dirent => dirent.name);

        // 存储所有 Promise
        const updatePromises: Promise<void>[] = [];

        // 遍历所有子文件夹，并检查是否是一个 Git 仓库
        directories.forEach(dir => {
            const repoPath = path.join(rootDir, dir);
            const gitPath = path.join(repoPath, '.git');

            // 如果是 Git 仓库，创建更新 Promise
            if (fs.existsSync(gitPath)) {
                console.log(`Updating repository: ${repoPath}`);
                const updatePromise = Utilities.execCommand('git pull', repoPath);
                updatePromises.push(updatePromise);
            } else {
                console.log(`${repoPath} is not a Git repository.`);
            }
        });

        // 等待所有仓库更新完成
        try {
            await Promise.all(updatePromises);
            console.log('All repositories have been updated successfully.');
        } catch (error) {
            console.error('One or more repositories failed to update:', error);
        }
    }

    /**
     * 扫描指定目录，返回该目录下所有文件的路径集合
     *
     * @param directoryPath 要扫描的目录路径
     * @return 包含所有文件相对路径的 Set 集合
     */
    public static scanFiles(directoryPath: string): { files: string[], name: string, count: number, lastUpdated: Date, isFromPlugin: boolean }[] {
        const sources: { files: string[], name: string, count: number, lastUpdated: Date, isFromPlugin: boolean }[] = [];
        directoryPath = path.resolve(directoryPath);
        if (fs.existsSync(directoryPath) && fs.lstatSync(directoryPath).isDirectory()) {
            const folders = fs.readdirSync(directoryPath);
            for (const folder of folders) {
                if (folder.startsWith('.')) continue;
                const fullPath = path.join(directoryPath, folder);
                let files: string[] = [];
                let latestFileTime: Date | null = null; // 用于记录最新文件的修改时间
                this.scanDirectory(fullPath, files, directoryPath, latestFileTime);
                
                sources.push({ 
                    files, 
                    name: folder, 
                    count: files.length, 
                    lastUpdated: latestFileTime || Utilities.getDate(), // 如果没有文件，默认当前时间
                    isFromPlugin: false 
                });
            }
        }
        return sources;
    }

    /**
     * 递归扫描目录及其子目录，收集所有文件的相对路径
     *
     * @param directory 当前扫描的目录
     * @param filePaths 存储文件路径的数组
     * @param rootPath  根目录路径，用于计算相对路径
     * @param latestFileTime 用于存储目录中最新的文件修改时间
     */
    private static scanDirectory(directory: string, filePaths: string[], rootPath: string, latestFileTime: Date | null): void {
        if (!fs.statSync(directory).isDirectory()) return;
        const files = fs.readdirSync(directory);
        files.forEach(file => {
            const fullPath = path.join(directory, file);
            // 忽略以点开头的文件或目录
            if (file.startsWith('.')) {
                return;
            }
            const stats = fs.lstatSync(fullPath);
            if (stats.isFile()) {
                // 计算相对于根目录的路径
                let relativePath = fullPath.substring(rootPath.length).replace(/\\/g, '/');
                if (!relativePath.startsWith('/')) {
                    relativePath = '/' + relativePath;
                }
                relativePath = '/files' + relativePath;
                filePaths.push(relativePath);

                // 更新最新的文件修改时间
                const fileModTime = stats.mtime;
                if (!latestFileTime || fileModTime > latestFileTime) {
                    latestFileTime = fileModTime;
                }
            } else if (stats.isDirectory()) {
                // 递归扫描子目录
                this.scanDirectory(fullPath, filePaths, rootPath, latestFileTime);
            }
        });
    }


    public static async wait(seconds: number): Promise<void> {
        return new Promise(resolve => {
            setTimeout(resolve, seconds * 1000);
        });
    }

    public static async getAvroBytes(files: File[]): Promise<Buffer> {
        return compress(FileListSchema.toBuffer(files as IFileInfo[]));
    }

    public static getUrl(file: File, cluster: ClusterEntity): string {
        if (file.url && cluster.isProxyCluster) return `${Utilities.getUrlByPath(file.url, '/download', cluster)}&origin=${file.url}`;
        return Utilities.getUrlByPath(file.hash, `/download/${file.hash}`, cluster);
    }
    public static getUrlByPath(hash: string, path: string, cluster: ClusterEntity): string {
        return `${Config.instance.server.forceHttps ? 'https' : 'http'}://${cluster.endpoint}:${cluster.port}/${path.substring(1)}?${Utilities.getSign(hash, cluster.clusterSecret)}`
    }

    public static async checkUrl(url: string): Promise<{ url: string; hash: string }> {
        try {
            const response = await HttpRequest.request(url, {
                responseType: 'buffer'
            });
            const responseData = response.body as Buffer;

            // 计算响应数据的哈希值
            const hash = crypto.createHash('sha1').update(responseData).digest('hex');

            return { url, hash };
        } catch (error) {
            const err = error as Error;
            console.error(`Error fetching ${url}:`, err.message);
            return { url, hash: `error: ${err.message}` };
        }
    }

    public static findDifferences(
        fileArray1: File[],
        fileArray2: File[],
        onlyRight: boolean = false
      ): File[] {
        const hashSet1 = new Set<string>(fileArray1.map(f => f.hash));
        const hashSet2 = new Set<string>(fileArray2.map(f => f.hash));
      
        return [
            ...onlyRight ? [] : fileArray1.filter(f =>!hashSet2.has(f.hash)), // 存在于 fileArray1 但不存在于 fileArray2
           ...fileArray2.filter(f =>!hashSet1.has(f.hash)) // 存在于 fileArray2 但不存在于 fileArray1
        ]
    }

    public static zip<T, U>(arr1: T[], arr2: U[]): [T, U][] {
        const length = Math.min(arr1.length, arr2.length); // 选择两个数组中较短的一个的长度
        const result: [T, U][] = []; // 初始化结果数组
      
        for (let i = 0; i < length; i++) {
          result.push([arr1[i], arr2[i]]);
        }
      
        return result;
    }

    public static async checkSpecfiedFiles(files: File[], cluster: ClusterEntity, attempt: number = -3): Promise<string | null> {
        let result: string | null = "Error: This value should never be returned. if you see this message, please contact the developer.";
    
        try {
            const urls = files.map(f => Utilities.getUrl(f, cluster));
            for (const [url, file] of Utilities.zip(urls, files)) {
                const realHash = file.hash;
                const remote = await Utilities.checkUrl(url);
                
                if (remote.hash !== realHash) {
                    if (attempt < 0) {
                        await Utilities.wait(3); // 等待 3 秒
                        const message = await Utilities.checkSpecfiedFiles([file], cluster, attempt + 1); // 递归重试
                        if (message) {
                            return message;
                        } else {
                            await Utilities.wait(3); // 等待 3 秒
                            continue;
                        }
                    }
                    
                    const remoteHash = remote.hash;
                    const differences = [
                        realHash,
                        remoteHash
                    ];
                    
                    result = `Error: Hash mismatch: ${differences.join(', ')}`;
                    return result;
                }

                // 等待 3 秒
                await Utilities.wait(3);
            }

            result = null;
        } catch (error) {
            result = `Error: ${(error as Error)?.message}`;
        }
    
        return result;
    }
    
    public static getRandomElement<T>(array: T[]): T | undefined {
        if (array.length === 0) return undefined; // 如果数组为空，返回 undefined
        const randomIndex = Math.floor(Math.random() * array.length);
        return array[randomIndex];
    }
    
    public static getRandomElements<T>(array: T[], count: number, allowDuplicates: boolean = true): T[] {
        const result: T[] = [];

        if (allowDuplicates) {
            for (let i = 0; i < count; i++) {
                const randomIndex = Math.floor(Math.random() * array.length);
                result.push(array[randomIndex]);
            }
        } else {
            if (count > array.length) {
                throw new Error("Count cannot be greater than the number of unique elements in the array when duplicates are not allowed.");
            }

            const tempArray = [...array]; // Create a copy of the array to avoid modifying the original one.
            for (let i = 0; i < count; i++) {
                const randomIndex = Math.floor(Math.random() * tempArray.length);
                result.push(tempArray.splice(randomIndex, 1)[0]);
            }
        }

        return result;
    }

    public static getWeightedRandomElement<T>(array: T[], weightFunc: (item: T) => number): T | null {
        if (array.length === 0) return null; // 如果数组为空，返回 undefined
    
        const weights = array.map(weightFunc);
        const totalWeight = weights.reduce((sum, weight) => sum + weight, 0);
    
        if (totalWeight === 0) return null;
    
        const random = Math.random() * totalWeight;
    
        let cumulativeWeight = 0;
        for (let i = 0; i < array.length; i++) {
            cumulativeWeight += weights[i];
            if (random < cumulativeWeight) {
                return array[i];
            }
        }
    
        return null;
    }    

    /**
    * 计算文件的 SHA-1 哈希值，并返回文件的字节数和最后的修改时间
    * @param filePath 文件路径
    * @returns Promise<FileInfo> 包含文件SHA-1哈希值、文件字节数和最后修改时间
    */
    public static async getFileInfoAsync(filePath: string): Promise<{ hash: string, size: number, lastModified: number }> {
        return new Promise((resolve, reject) => {
            // 使用 fs.stat 获取文件的元信息
            fs.stat(filePath, (err, stats) => {
                if (err) {
                    return reject(`无法获取文件信息: ${err.message}`);
                }

                // 创建 SHA-1 哈希
                const hash = crypto.createHash('sha1');
                const stream = fs.createReadStream(filePath);

                // 逐块更新哈希
                stream.on('data', (data) => {
                    hash.update(data);
                });

                // 文件读取完毕，返回 SHA-1 哈希及文件信息
                stream.on('end', () => {
                    const sha1 = hash.digest('hex');
                    resolve({
                        hash: sha1,
                        size: stats.size,                 // 文件的字节数
                        lastModified: stats.mtime.getTime()         // 文件最后的修改时间
                    });
                });

                // 文件读取或哈希计算出错时处理
                stream.on('error', (err) => {
                    reject(`文件读取出错: ${err.message}`);
                });
            });
        });
    }

    public static computeSignature(challenge: string, signature: string, key: string): boolean {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(challenge);
        const calculatedSignature = hmac.digest('hex').toLowerCase();
        return calculatedSignature === signature.toLowerCase();
    }

    public static verifyClusterRequest(req: Request): boolean {
        return JwtHelper.instance.verifyToken(req.headers.authorization?.split(' ').at(-1), 'cluster') instanceof Object;
    }

    public static tryGetRequestCluster<T>(req: Request): T {
        return JwtHelper.instance.verifyToken(req.headers.authorization?.split(' ').at(-1), 'cluster') as T;
    }

    public static toUrlSafeBase64String(buffer: Buffer): string {
        return buffer.toString('base64')
            .replace(/\+/g, '-')  // Replace '+' with '-'
            .replace(/\//g, '_')  // Replace '/' with '_'
            .replace(/=+$/, '');  // Remove trailing '='
    }    

    public static getSign(path: string, secret: string): string | null {
        let sha1: crypto.Hash;
        try {
            sha1 = crypto.createHash('sha1');
        } catch (e) {
            console.error(e);
            return null;
        }
        
        const timestamp = Utilities.getDate(5, "min").getTime();
        const e = timestamp.toString(36);
        const signBytes = sha1.update(secret + path + e).digest();
        const sign = Utilities.toUrlSafeBase64String(signBytes);
        
        return `s=${sign}&e=${e}`;
    }

    /**
     * verifyUser
     */
    public static verifyUser(req: Request, res: Response, db: SQLiteHelper): boolean {
        const id = (JwtHelper.instance.verifyToken(req.cookies.token, 'user') as { userId: number })?.userId;
        if (!id) {
            res.status(401).send('Unauthorized');
            return false;
        }
        const user = db.getEntity<UserEntity>(UserEntity, id);
        if (!user) {
            res.status(401).send('Unauthorized');
            return false;
        }
        return true;
    }

    public static verifyAdmin(req: Request, res: Response, db: SQLiteHelper): boolean {
        const id = (JwtHelper.instance.verifyToken(req.cookies.adminToken, 'admin') as { userId: number })?.userId;
        if (!id) {
            res.status(401).send('Unauthorized');
            return false;
        }
        const user = db.getEntity<UserEntity>(UserEntity, id);
        if (!user) {
            res.status(401).send('Unauthorized');
            return false;
        }
        if (!user.isSuperUser) {
            res.status(403).send('Forbidden');
            return false;
        }
        return true;
    }

    // 将布尔数组转换为整数（BigInt）
    public static booleansToInt(bits: boolean[]): number {
        return bits.reduce((acc, bit, index) => {
            if (bit) {
                acc |= (1 << index); // 设置第 index 位为 1
            }
            return acc;
        }, 0);
    }

    // 将 BigInt 整数转换为布尔数组
    public static intToBooleans(value: number, size: number): boolean[] {
        const bits = [];
        for (let i = 0; i < size; i++) {
            bits.push((value & (1 << i)) !== 0); // 检查第 i 位是否为 1
        }
        return bits;
    }

    public static getCurrentTime(): string {
        return Utilities.getDateTime(new Date());
    }

    public static getDateTime(date: Date): string {
        const year = date.getFullYear();
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const day = date.getDate().toString().padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    public static getCurrentDate(): string {
        return Utilities.getDateString(new Date());
    }

    public static getDateString(date: Date): string {
        const year = date.getFullYear();
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const day = date.getDate().toString().padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    public static async doMeasure(url: string): Promise<number> {
        try {
            // 发出请求，接收下载数据
            const response = await HttpRequest.request(url, {
                responseType: 'buffer',  // 以二进制数据形式接收
                timeout: { request: 60000 }, // 设置请求超时时间 (可选)
            });
    
            // 获取响应时间数据
            const timings = response.timings;
    
            // 计算总下载时间（秒）
            const timeTakenInSeconds = (timings.phases.download || NaN) / 1000;
    
            // 获取下载的数据大小（字节）
            const dataSizeInBytes = response.rawBody.length;
    
            // 计算下载带宽（字节每秒）
            const bandwidthBps = dataSizeInBytes / timeTakenInSeconds;
    
            // 将带宽转换为 Mbps
            const bandwidthMbps = (bandwidthBps * 8) / (1024 * 1024); // 1 Mbps = 1024 * 1024 bps
    
            return Math.round(bandwidthMbps);
        } catch (error) {
            console.error(error);
        }
        return NaN;
    }

    public static filterMinutes(dates: Date[], minutes: number = 15): void {
        const now = Date.now();
        const ms = minutes * 60 * 1000; // 15分钟的毫秒数
    
        // 过滤出15分钟之外的日期
        const filteredDates = dates.filter(date => now - date.getTime() <= ms);
    
        // 如果所有日期都在最近15分钟内，返回 true；否则，更新数组并返回 false
        if (filteredDates.length !== dates.length) {
            // 删除15分钟之外的日期
            dates.length = 0;
            dates.push(...filteredDates);
        }
    }

    public static getTimestamp(date: Date | undefined = undefined): number {
        return date? date.getTime() : Date.now();
    }

    public static getDate(after: number = 0, unit: "ms" | "s" | "min" | "hour" | "day" | "month" | "year" = "day"): Date {
        switch (unit) {
            case "ms":
                return new Date(Date.now() + after);
            case "s":
                return new Date(Date.now() + after * 1000);
            case "min":
                return new Date(Date.now() + after * 60 * 1000);
            case "hour":
                return new Date(Date.now() + after * 60 * 60 * 1000);
            case "day":
                return new Date(Date.now() + after * 24 * 60 * 60 * 1000);
            case "month":
                return new Date(Date.now() + after * 30 * 24 * 60 * 60 * 1000);
            case "year":
                return new Date(Date.now() + after * 365 * 24 * 60 * 60 * 1000);
        }
    }

    public static checkName(name: string | null): boolean {
        if (!name) return true;
        return !bannedCharacters.test(name);
    };
    
    public static checkNameRule(name: string): boolean | string {
        return bannedCharacters.test(name) ? '名称不能包含特殊字符' : true;
    }
}