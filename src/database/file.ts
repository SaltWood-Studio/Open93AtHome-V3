import { Utilities } from "../utilities.js";

export class File {
    public path: string;
    public hash: string;
    public size: number;
    public lastModified: number;
    public encodedPath: string;

    public constructor() {
        this.path = "/path/to/file";
        this.hash = "0000000000000000000000000000000000000000";
        this.size = 0;
        this.lastModified = 0;
        this.encodedPath = encodeURI(this.path);
    }

    public static createInstance(path: string, hash: string, size: number, lastModified: number): File {
        const file = new File();
        file.path = path.substring(1);
        file.hash = hash;
        file.size = size;
        file.lastModified = lastModified;
        file.encodedPath = encodeURI(file.path);
        return file;
    }

    public static async createInstanceFromPath(path: string): Promise<File> {
        return new Promise<File>(async (resolve, reject) => {
            const file = new File();
            const information = await Utilities.getFileInfoAsync(path);
            file.path = path.substring(1);
            file.hash = information.hash;
            file.size = information.size;
            file.lastModified = information.lastModified;
            file.encodedPath = encodeURI(file.path);
            resolve(file);
        });
    }
}

export interface IFileInfo {
    encodedPath: string
    hash: string
    size: number
    lastModified: number
}
