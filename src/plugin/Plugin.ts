// Plugin.ts
export abstract class Plugin {
    abstract init(): void;
    abstract getName(): string;
}