import * as fs from 'fs';
import * as path from 'path';
import { Config } from '../Config.js';

export class StatsStorage {
    public readonly id: string;
    private data: { date: string, hits: number, bytes: number }[];
    private filePath: string;
    private saveInterval: NodeJS.Timeout;
    private dataUpdated: boolean;  // 标志是否有数据更新

    constructor(id: string) {
        this.id = id;
        this.filePath = path.join(Config.getInstance().statsDir, `${this.id}.stats`);
        this.data = [];
        this.dataUpdated = false;  // 初始时数据未更新

        // 如果文件存在，加载已有的数据
        if (fs.existsSync(this.filePath)) {
            this.loadFromFile();
        }

        // 每10分钟保存一次数据（如果有更新）
        this.saveInterval = setInterval(() => {
            this.maybeWriteToFile();
        }, 10 * 60 * 1000);
    }

    public addData({ hits, bytes }: { hits: number, bytes: number }): void {
        const today = new Date().toISOString().split('T')[0];

        let todayData = this.data.find(entry => entry.date === today);
        if (!todayData) {
            todayData = { date: today, hits: 0, bytes: 0 };
            this.data.push(todayData);
            if (this.data.length > 30) {
                this.data.shift(); // 保持只存30天的数据
            }
        }

        todayData.hits += hits;
        todayData.bytes += bytes;
        this.dataUpdated = true;  // 数据已更新
    }

    public getTodayStats(): { hits: number, bytes: number } {
        const today = new Date().toISOString().split('T')[0];
        const todayData = this.data.find(entry => entry.date === today);
        if (todayData) {
            return { hits: todayData.hits, bytes: todayData.bytes };
        } else {
            return { hits: 0, bytes: 0 };
        }
    }

    public getLast30DaysStats(): { date: string, hits: number, bytes: number }[] {
        const now = new Date();
        // const today = now.toISOString().split('T')[0];

        // 创建一个包含最近30天的日期和默认数据的映射
        const dateMap: { [key: string]: { hits: number, bytes: number } } = {};

        // 填充最近30天的数据
        for (let i = 0; i < 30; i++) {
            const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
            dateMap[date] = { hits: 0, bytes: 0 };
        }

        // 更新映射中的数据
        for (const entry of this.data) {
            dateMap[entry.date] = { hits: entry.hits, bytes: entry.bytes };
        }

        // 将映射转换为数组，并按日期排序
        return Object.keys(dateMap)
            .sort()
            .map(date => ({
                date,
                hits: dateMap[date].hits,
                bytes: dateMap[date].bytes
            }));
    }

    private maybeWriteToFile(): void {
        if (this.dataUpdated) {
            this.writeToFile();
            this.dataUpdated = false;  // 重置更新标志
        }
    }

    private writeToFile(): void {
        const fileContent = this.data.map(entry => `${entry.date} ${entry.hits} ${entry.bytes}`).join('\n');
        fs.writeFileSync(this.filePath, fileContent, 'utf8');
    }

    private loadFromFile(): void {
        const fileContent = fs.readFileSync(this.filePath, 'utf8');
        const lines = fileContent.split('\n').filter(line => line.trim() !== '');

        this.data = lines.map(line => {
            const [date, hits, bytes] = line.split(' ');
            return { date, hits: Number(hits), bytes: Number(bytes) };
        });
    }

    public stopAutoSave(): void {
        clearInterval(this.saveInterval);
        this.maybeWriteToFile(); // 在停止时立即保存数据（如果有更新）
    }
}
