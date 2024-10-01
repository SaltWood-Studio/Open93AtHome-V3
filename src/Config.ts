import dotenv from 'dotenv'
import env from 'env-var'
import { Utilities } from './Utilities.js'
import RateLimiter from './RateLimit.js'

export class Config {
    public static instance: Config

    public readonly githubOAuthClientId: string = env.get('GITHUB_OAUTH_CLIENT_ID').default("").asString()
    public readonly githubOAuthClientSecret: string = env.get('GITHUB_OAUTH_CLIENT_SECRET').default("").asString()
    public readonly githubOAuthCallbackUrl: string = env.get('GITHUB_OAUTH_CALLBACK_URL').default("").asString()
    public readonly githubUrl: string = env.get('GITHUB_URL').default("github.com").asString()
    public readonly githubApiUrl: string = env.get('GITHUB_API_URL').default("api.github.com").asString()
    public readonly statsDir: string = env.get('STATISTICS_DIRECTORY').default("./stats").asString()
    public readonly port: number = env.get('PORT').default(9388).asPortNumber()
    public readonly adminToken: string = env.get('ADMIN_TOKEN').default(Utilities.generateRandomString(24)).asString()
    public readonly concurrency: number = env.get('CONCURRENCY').default(10).asIntPositive()
    public readonly forceNoOpen: boolean = env.get('FORCE_NO_OPEN').default("false").asBool();
    public readonly noWarden: boolean = env.get('NO_WARDEN').default("false").asBool();
    public readonly forceHttps: boolean = env.get('FORCE_HTTPS').default("false").asBool();
    public readonly failAttemptsToBan: number = env.get('FAIL_ATTEMPTS_TO_BAN').default(20).asIntPositive();
    public readonly failAttemptsDuration: number = env.get('FAIL_ATTEMPTS_DURATION').default(15).asIntPositive();
    // public readonly requestRateLimit: number = env.get('REQUEST_RATE_LIMIT').default(10).asIntPositive();

    // 开发变量
    public readonly sourceIpHeader: string = env.get('SOURCE_IP_HEADER').default("x-real-ip").asString();
    public readonly enableDebugRoutes: boolean = env.get('ENABLE_DEBUG_ROUTES').default("false").asBool();

    public static readonly version: string = "3.1.0";

    private constructor() { }

    public static getInstance(): Config {
        if (!Config.instance) {
            Config.instance = new Config()
        }
        return Config.instance
    }

    public static init() {
        if (!Config.instance) {
            Config.instance = new Config()
            // RateLimiter.RATE_LIMIT = Config.instance.requestRateLimit;
        }
    }
}

dotenv.config()