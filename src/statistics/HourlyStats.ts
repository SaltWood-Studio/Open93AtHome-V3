import * as fs from 'fs';
import * as path from 'path';
import { Config } from '../Config.js';
import { Utilities } from '../Utilities.js';

export class HourlyStatsStorage {
    private data: { date: string, hourlyStats: { hour: string, hits: number, bytes: number }[] }[];
    private filePath: string;
    private saveInterval: NodeJS.Timeout;
    private dataUpdated: boolean;

    constructor() {
        this.filePath = path.join(Config.getInstance().statsDir, `center.stats.json`);
        this.data = [];
        this.dataUpdated = false;

        if (fs.existsSync(this.filePath)) {
            this.loadFromFile();
        }

        this.saveInterval = setInterval(() => {
            this.maybeWriteToFile();
        }, 10 * 60 * 1000);
    }

    public today(): { hits: number, bytes: number } {
        const date = Utilities.getCurrentDate();
        let today = { hits: 0, bytes: 0 };
        this.data.find(entry => entry.date === date)?.hourlyStats.forEach(hourData => {
            today.hits += hourData.hits;
            today.bytes += hourData.bytes;
        });
        return today;
    }

    public addData({ hits, bytes }: { hits: number, bytes: number }): void {
        const now = new Date();
        const date = Utilities.getDateDate(now);
        const hour = now.getHours().toString().padStart(2, '0');

        let dayData = this.data.find(entry => entry.date === date);
        if (!dayData) {
            dayData = { date: date, hourlyStats: [] };
            this.data.push(dayData);
            if (this.data.length > 30) {
                this.data.shift();
            }
        }

        let hourData = dayData.hourlyStats.find(entry => entry.hour === hour);
        if (!hourData) {
            hourData = { hour: hour, hits: 0, bytes: 0 };
            dayData.hourlyStats.push(hourData);
            if (dayData.hourlyStats.length > 24) {
                dayData.hourlyStats.shift();
            }
        }

        hourData.hits += hits;
        hourData.bytes += bytes;
        this.dataUpdated = true;
    }

    public getLast30DaysHourlyStats(): { date: string, hits: number, bytes: number }[][] {
        const result: { date: string, hits: number, bytes: number }[][] = [];
        const now = new Date();

        for (let i = 0; i < 30; i++) {
            const dateString = Utilities.getDateDate(new Date(now.getTime() - i * 24 * 60 * 60 * 1000));

            const dayData = this.data.find(entry => entry.date === dateString);
            const dayResult: { date: string, hits: number, bytes: number }[] = [];

            for (let hour = 0; hour < 24; hour++) {
                const hourString = hour.toString().padStart(2, '0');
                const hourData = dayData?.hourlyStats.find(entry => entry.hour === hourString);

                if (hourData) {
                    dayResult.push({
                        date: `${dateString}T${hourString}:00:00`,
                        hits: hourData.hits,
                        bytes: hourData.bytes
                    });
                } else {
                    dayResult.push({
                        date: `${dateString}T${hourString}:00:00`,
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
            this.dataUpdated = false;
        }
    }

    private writeToFile(): void {
        const fileContent = JSON.stringify(this.data);
        fs.writeFileSync(this.filePath, fileContent, 'utf8');
    }

    private loadFromFile(): void {
        const fileContent = fs.readFileSync(this.filePath, 'utf8');
        this.data = JSON.parse(fileContent);
    }

    public stopAutoSave(): void {
        clearInterval(this.saveInterval);
        this.maybeWriteToFile();
    }
}
