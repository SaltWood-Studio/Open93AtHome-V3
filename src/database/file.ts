import { Utilities } from "../utilities";

export class File {
    public path: string;
    public hash: string;
    public size: number;
    public lastModified: number;

    public constructor() {
        this.path = "/path/to/file";
        this.hash = "0000000000000000000000000000000000000000";
        this.size = 0;
        this.lastModified = 0;
    }

    public static createInstance(path: string, hash: string, size: number, lastModified: number): File {
        const file = new File();
        file.path = path;
        file.hash = hash;
        file.size = size;
        file.lastModified = lastModified;
        return file;
    }

    public static createInstanceFromPath(path: string): File {
        const file = new File();
        const information = Utilities.getFileInfoSync(path);
        file.path = path;
        file.hash = information.hash;
        file.size = information.size;
        file.lastModified = information.lastModified;
        return file;
    }
}