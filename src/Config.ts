import json5 from 'json5';
import { defaultInstance } from './RateLimiter.js';
import fs from 'fs';

export const version = "3.2.1-pre3";

export class Config {
    private static _instance: Config;
    public static readonly FILENAME = 'config.json5';
    private static _fsWatcher: fs.FSWatcher;

    public readonly dns: {
        type: string;
        secretId: string;
        secretToken: string;
        domain: string;
        contactEmail: string;
    } = {
        type: "cloudflare",
        secretId: "",
        secretToken: "",
        domain: "",
        contactEmail: ""
    };

    public readonly github: {
        oAuthClientId: string;
        oAuthClientSecret: string;
        oAuthCallbackUrl: string;
        url: string;
        apiUrl: string;
    } = {
        oAuthClientId: "",
        oAuthClientSecret: "",
        oAuthCallbackUrl: "",
        url: "github.com",
        apiUrl: "api.github.com"
    };

    public readonly server: {
        host: string;
        port: number;
        concurrency: number;
        forceNoOpen: boolean;
        noWarden: boolean;
        forceHttps: boolean;
        requestCert: boolean;
    } = {
        host: "127.0.0.1",
        port: 9388,
        concurrency: 10,
        forceNoOpen: false,
        noWarden: false,
        forceHttps: false,
        requestCert: false
    };

    public readonly security: {
        failAttemptsToBan: number;
        failAttemptsDuration: number;
        requestRateLimit: number;
    } = {
        failAttemptsToBan: 0,
        failAttemptsDuration: 0,
        requestRateLimit: 0
    };

    public readonly update: {
        checkInterval: number;
        shownDays: number;
    } = {
        checkInterval: 0,
        shownDays: 15
    };

    public readonly dev: {
        sourceIpHeader: string;
        debug: boolean;
        disableAccessLog: boolean;
    } = {
        sourceIpHeader: "x-real-ip",
        debug: false,
        disableAccessLog: false
    };

    public readonly zerossl: {
        kid: string;
        hmacKey: string;
    } = {
        kid: "",
        hmacKey: ""
    };

    public static readonly version: string = version;

    private constructor() {
        this.loadConfig();
    }

    private loadConfig(): void {
        if (fs.existsSync(Config.FILENAME)) {
            const data = fs.readFileSync(Config.FILENAME, 'utf-8');
            const configData = json5.parse(data);

            Object.keys(configData).forEach((key) => {
                if (key in this) {
                    this.validateAndAssign(key as keyof Config, configData[key]);
                }
            });
        }
        defaultInstance.RATE_LIMIT = this.security.requestRateLimit;
    }

    private validateAndAssign(field: keyof Config, value: any): void {
        const fieldType = typeof this[field];
        if (fieldType === 'string' && typeof value !== 'string') {
            throw new Error(`Invalid type for field "${field}". Expected string but got ${typeof value}.`);
        }
        if (fieldType === 'number' && typeof value !== 'number') {
            throw new Error(`Invalid type for field "${field}". Expected number but got ${typeof value}.`);
        }
        if (fieldType === 'boolean' && typeof value !== 'boolean') {
            throw new Error(`Invalid type for field "${field}". Expected boolean but got ${typeof value}.`);
        }
        if (fieldType === 'object' && typeof value === 'object' && value !== null) {
            const expectedObjectType = this[field] as unknown as object;
            if (Array.isArray(value)) {
                throw new Error(`Invalid type for field "${field}". Expected object but got array.`);
            }
            Object.keys(expectedObjectType).forEach(subKey => {
                if (!(subKey in value)) {
                    (value as any)[subKey] = (expectedObjectType as any)[subKey];
                }
            });
        }
        (this as any)[field] = value;
    }

    public static getInstance(): Config {
        if (!Config._instance) {
            Config._instance = new Config();
            Config._fsWatcher = fs.watch(Config.FILENAME, () => {
                console.log('[Config] Config file changed. Reloading...');
                Config._instance.loadConfig();
            });
        }
        return Config._instance;
    }

    public static get instance(): Config {
        return Config.getInstance();
    }

    public static get fsWatcher(): fs.FSWatcher {
        return Config._fsWatcher;
    }
}
