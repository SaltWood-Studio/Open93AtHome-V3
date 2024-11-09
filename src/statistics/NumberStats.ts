import path from "path";
import fs from "fs";
import { Utilities } from "../Utilities.js";

export class NumberStorage {
    public readonly id: string;
    private data: { date: string, number: number }[];
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
        const today = Utilities.getCurrentDate();

        let todayData = this.data.find(d => d.date === today);
        if (!todayData) {
            todayData = { date: today, number: 0 };
            this.data.push(todayData);
            if (this.data.length > 30) {
                this.data.shift();
            }
        }

        if (!todayData.number) todayData.number = 0;
        todayData.number += data;
        this.dataUpdated = true;
    }

    public getTodayStats(): number {
        const today = Utilities.getCurrentDate();
        const todayData = this.data.find(d => d.date === today);
        return todayData? todayData.number : NaN;
    }

    public getLast30DaysStats(): number[] {
        const now = new Date();
        const data = this.data.map(d => d.number);
        return [...(new Array(30 - data.length).fill(0)), ...data];
    }

    private maybeWriteToFile(): void {
        if (this.dataUpdated) {
            this.writeToFile();
            this.dataUpdated = false;
        }
    }

    private writeToFile(): void {
        const data = JSON.stringify(this.data, null, 2);
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