import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { dir } from 'console';

export class Utilities {
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

    public static getFileInfoSync(filePath: string): { hash: string, size: number, lastModified: number } {
        try {
            const stats = fs.statSync(filePath);
            const hash = crypto.createHash('sha256');
            let fileSize = 0;
    
            const data = fs.readFileSync(filePath);
            hash.update(data);
            fileSize = data.length;
    
            return {
                hash: hash.digest('hex'),
                size: fileSize,
                lastModified: stats.mtime.getTime()
            };
    
        } catch (err) {
            return { hash: '0000000000000000000000000000000000000000', size: 0, lastModified: 0 };
        }
    }
}
