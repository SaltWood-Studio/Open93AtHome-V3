import path from "path";
import fs from "fs";
import { Utilities } from "../Utilities.js";

export class NumberStorage {
    public readonly id: string;
    private data: { date: string, data: number[] }[];
    private filePath: string;
    private saveInterval: NodeJS.Timeout;
    private dataUpdated: boolean;
    
    constructor(id: string) {
        this.id = id;
        this.data = [];
        this.filePath = path.join('./stats', `${this.id}.stats.json`);
        this.dataUpdated = false;

        if (fs.existsSync(this.filePath)) {
            this.loadFromFile();
        }

        this.saveInterval = setInterval(() => {
            this.maybeWriteToFile();
        }, 10 * 60 * 1000);
    }

    public addData(data: number): void {
        if (this.data.length > 30) this.data.shift();

        const now = new Date();
        const date = Utilities.getDateDate(now);
        const hour = now.getHours();

        let todayData = this.data.find(d => d.date === date);
        if (!todayData) {
            todayData = { date, data: [] };
            this.data.push(todayData);
        }

        if (todayData.data.length !== 24) todayData.data = new Array(24).fill(0);

        todayData.data[hour] += data;
        this.dataUpdated = true;
    }

    public getTodayStats(): number[] {
        const now = new Date();
        const date = Utilities.getDateDate(now);

        const todayData = this.data.find(d => d.date === date);
        if (!todayData) return new Array(24).fill(0);

        return todayData.data;
    }

    public getLast30DaysHourlyStats(): number[][] {
        return [...(new Array(Math.max(30 - this.data.length, 0)).fill(new Array(24).fill(0))), ...this.data.map(d => d.data)];
    }

    private maybeWriteToFile(): void {
        if (this.dataUpdated) {
            this.writeToFile();
            this.dataUpdated = false;
        }
    }

    private writeToFile(): void {
        const data = JSON.stringify(this.data);
        fs.writeFileSync(this.filePath, data);
    }

    private loadFromFile(): void {
        try {
            const data = fs.readFileSync(this.filePath, 'utf8');
            this.data = JSON.parse(data);
        }
        catch (e) {
            this.data = [];
        }
    }

    public stopAutoSave(): void {
        clearInterval(this.saveInterval);
        this.maybeWriteToFile();
    }
}