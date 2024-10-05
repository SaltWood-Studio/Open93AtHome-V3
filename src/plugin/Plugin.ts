import { File } from '../database/File.js';
import { Request, Response } from "express";

export abstract class Plugin {
    public abstract get isFilePlugin(): boolean;

    public abstract init(): void;
    public abstract getName(): string;

    public abstract getFileSourceName(): string;
    public abstract getSourceAddress(): string;

    public abstract updateFiles(): Promise<void>;

    // 任何插件都应该在 updateFiles 未结束之前阻塞此方法的调用
    public abstract getFiles(): Promise<File[]>;

    public abstract express(file: File, req: Request, res: Response): Promise<void>;
    public abstract exists(file: File): boolean;
}