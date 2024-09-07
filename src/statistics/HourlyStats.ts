import * as fs from 'fs';
import * as path from 'path';
import { Config } from '../Config.js';

export class HourlyStatsStorage {
    private data: { date: string, hourlyStats: { hour: string, hits: number, bytes: number }[] }[];
    private filePath: string;
    private saveInterval: NodeJS.Timeout;
    private dataUpdated: boolean;  // 标志是否有数据更新

    public today(): { hits: number, bytes: number } {
        const now = new Date();
        const date = now.toISOString().split('T')[0];
        let today = { hits: 0, bytes: 0 };
        this.data.find(entry => entry.date === date)?.hourlyStats.forEach(hourData => {
            today.hits += hourData.hits;
            today.bytes += hourData.bytes;
        });
        return today;
    }

    constructor() {
        this.filePath = path.join(Config.getInstance().statsDir, `center.stats`);
        this.data = [];
        this.dataUpdated = false;  // 初始时数据未更新

        // 如果文件存在，加载已有的数据
        if (fs.existsSync(this.filePath)) {
            this.loadFromFile();
        }

        // 每10分钟保存一次数据（如果有更新）
        this.saveInterval = setInterval(() => {
            this.maybeWriteToFile();
        }, 10 * 60 * 1000); // 10分钟
    }

    public addData({ hits, bytes }: { hits: number, bytes: number }): void {
        const now = new Date();
        const date = now.toISOString().split('T')[0];
        const hour = now.getUTCHours().toString().padStart(2, '0');  // 获取当前小时（以UTC表示）

        let dayData = this.data.find(entry => entry.date === date);
        if (!dayData) {
            dayData = { date: date, hourlyStats: [] };
            this.data.push(dayData);
            if (this.data.length > 30) {
                this.data.shift(); // 保持只存30天的数据
            }
        }

        let hourData = dayData.hourlyStats.find(entry => entry.hour === hour);
        if (!hourData) {
            hourData = { hour: hour, hits: 0, bytes: 0 };
            dayData.hourlyStats.push(hourData);
            if (dayData.hourlyStats.length > 24) {
                dayData.hourlyStats.shift(); // 保持只存24小时的数据
            }
        }

        hourData.hits += hits;
        hourData.bytes += bytes;
        this.dataUpdated = true;  // 数据已更新
    }

    public getLast30DaysHourlyStats(): { date: string, hits: number, bytes: number }[][] {
        // 构建返回的二维数组
        const result: { date: string, hits: number, bytes: number }[][] = [];

        // 获取当前日期
        const now = new Date();

        for (let i = 0; i < 30; i++) {
            // 获取前第 i 天的日期
            const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
            const dateString = date.toISOString().split('T')[0];

            // 找到当前日期的数据
            const dayData = this.data.find(entry => entry.date === dateString);
            const dayResult: { date: string, hits: number, bytes: number }[] = [];

            for (let hour = 0; hour < 24; hour++) {
                const hourString = hour.toString().padStart(2, '0');
                const hourData = dayData?.hourlyStats.find(entry => entry.hour === hourString);

                if (hourData) {
                    dayResult.push({
                        date: `${dateString}T${hourString}:00:00Z`,
                        hits: hourData.hits,
                        bytes: hourData.bytes
                    });
                } else {
                    dayResult.push({
                        date: `${dateString}T${hourString}:00:00Z`,
                        hits: 0,
                        bytes: 0
                    });
                }
            }

            result.push(dayResult);
        }

        return result;
    }

    private maybeWriteToFile(): void {
        if (this.dataUpdated) {
            this.writeToFile();
            this.dataUpdated = false;  // 重置更新标志
        }
    }

    private writeToFile(): void {
        const fileContent = this.data.map(day => {
            return day.hourlyStats.map(hourData => `${day.date} ${hourData.hour} ${hourData.hits} ${hourData.bytes}`).join('\n');
        }).join('\n');
        fs.writeFileSync(this.filePath, fileContent, 'utf8');
    }

    private loadFromFile(): void {
        const fileContent = fs.readFileSync(this.filePath, 'utf8');
        const lines = fileContent.split('\n').filter(line => line.trim() !== '');

        this.data = [];
        let currentDay: { date: string, hourlyStats: { hour: string, hits: number, bytes: number }[] } | null = null;

        for (const line of lines) {
            const [date, hour, hits, bytes] = line.split(' ');
            if (!currentDay || currentDay.date !== date) {
                if (currentDay) {
                    this.data.push(currentDay);
                }
                currentDay = { date: date, hourlyStats: [] };
            }
            currentDay.hourlyStats.push({ hour, hits: Number(hits), bytes: Number(bytes) });
        }

        if (currentDay) {
            this.data.push(currentDay);
        }
    }

    public stopAutoSave(): void {
        clearInterval(this.saveInterval);
        this.maybeWriteToFile(); // 在停止时立即保存数据（如果有更新）
    }
}
