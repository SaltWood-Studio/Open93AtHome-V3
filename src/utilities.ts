import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { dir } from 'console';
import { Request } from 'express';
import JwtHelper from './jwt-helper';
import { File, IFileInfo } from './database/file';
import { compress } from '@mongodb-js/zstd';
import avsc from 'avsc';
import axios from 'axios';
import { exec } from 'child_process';

export const FileListSchema = avsc.Type.forSchema({
  type: 'array',
  items: {
    name: 'files',
    type: 'record',
    fields: [
      {name: 'path', type: 'string'},
      {name: 'hash', type: 'string'},
      {name: 'size', type: 'long'},
      {name: 'lastModified', type: 'long'},
    ],
  },
})

export class Utilities {
    public static generateRandomString(length: number): string {
        return crypto.randomBytes(length).toString('hex').slice(0, length);
    }

    // 将 exec 封装为 Promise
    public static execCommand(command: string, cwd: string): Promise<void> {
        return new Promise((resolve, reject) => {
            exec(command, { cwd }, (error, stdout, stderr) => {
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
    public static scanFiles(directoryPath: string): string[] {
        const filePaths: string[] = [];
        directoryPath = path.resolve(directoryPath);
        if (fs.existsSync(directoryPath) && fs.lstatSync(directoryPath).isDirectory()) {
            this.scanDirectory(directoryPath, filePaths, directoryPath);
        }
        return filePaths;
    }

    /**
     * 递归扫描目录及其子目录，收集所有文件的相对路径
     *
     * @param directory 当前扫描的目录
     * @param filePaths 存储文件路径的 Set 集合
     * @param rootPath  根目录路径，用于计算相对路径
     */
    private static scanDirectory(directory: string, filePaths: string[], rootPath: string): void {
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
            } else if (stats.isDirectory()) {
                // 递归扫描子目录
                this.scanDirectory(fullPath, filePaths, rootPath);
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

    public static getRandomElement<T>(array: T[]): T | undefined {
        if (array.length === 0) return undefined; // 如果数组为空，返回 undefined
        const randomIndex = Math.floor(Math.random() * array.length);
        return array[randomIndex];
    }

    public static async checkUrls(urls: string[]): Promise<{ url: string; hash: string }[]> {
        const results: { url: string; hash: string }[] = [];
    
        for (const url of urls) {
            try {
                const response = await axios.get(url, { responseType: 'arraybuffer' });
                const responseData = response.data as Buffer;
    
                // 计算响应数据的哈希值
                const hash = crypto.createHash('sha1').update(responseData).digest('hex');
    
                results.push({ url, hash });

                await this.wait(2); // 限制请求频率
            } catch (error) {
                const err = error as Error;
                console.error(`Error fetching ${url}:`, err.message);
                results.push({ url, hash: 'error' });
            }
        }
    
        return results;
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

    public static getFileInfoSync(filePath: string): { hash: string, size: number, lastModified: number } {
        try {
            // 获取文件的元数据，包括大小和最后修改时间
            const stats = fs.statSync(filePath);
            const hash = crypto.createHash('sha1');
            
            // 使用流式读取文件，避免将整个文件加载到内存
            const fileStream = fs.createReadStream(filePath);
            fileStream.on('data', (chunk) => hash.update(chunk));
            
            // 同步结束流
            fileStream.on('end', () => {});
    
            // 返回文件的哈希值、大小和最后修改时间
            return {
                hash: hash.digest('hex'),
                size: stats.size,
                lastModified: stats.mtime.getTime()
            };
            
        } catch (err) {
            return { hash: '0000000000000000000000000000000000000000', size: 0, lastModified: 0 };
        }
    }

    public static computeSignature(challenge: string, signature: string, key: string): boolean {
        const hmac = crypto.createHmac('sha1', key);
        hmac.update(challenge);
        const calculatedSignature = hmac.digest('hex').toLowerCase();
        return calculatedSignature === signature.toLowerCase();
    }

    public static verifyClusterRequest(req: Request): boolean {
        return JwtHelper.getInstance().verifyToken(req.headers.authorization?.split(' ').at(-1), 'cluster') instanceof Object;
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
        
        const timestamp = Date.now() + 5 * 60 * 1000;
        const e = timestamp.toString(36);
        const signBytes = sha1.update(secret + path + e).digest();
        const sign = Utilities.toUrlSafeBase64String(signBytes);
        
        return `s=${sign}&e=${e}`;
    }
}
