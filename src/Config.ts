import dotenv from 'dotenv'
import env from 'env-var'
import { defaultInstance } from './RateLimiter.js'

export const version = "3.2.1-pre3";

export class Config {
    public static instance: Config

    public readonly enableRequestCertificate: boolean = env.get('ENABLE_REQUEST_CERTIFICATE').default("false").asBool();
    public readonly dnsType: string = env.get('DNS_TYPE').default("cloudflare").asString();
    public readonly dnsSecretId: string = env.get('DNS_SECRET_ID').default("").asString();
    public readonly dnsSecretToken: string = env.get('DNS_SECRET_TOKEN').default("").asString();
    public readonly dnsDomain: string = env.get('DNS_DOMAIN').default("").asString();
    public readonly domainContactEmail: string = env.get('DOMAIN_CONTACT_EMAIL').default("").asString();
    // public readonly acmeStaging: boolean = env.get('ACME_STAGING').default("false").asBool();

    public readonly zerosslKid: string = env.get('ZEROSSL_KID').default("").asString();
    public readonly zerosslHmacKey: string = env.get('ZEROSSL_HMAC_KEY').default("").asString();

    public readonly githubOAuthClientId: string = env.get('GITHUB_OAUTH_CLIENT_ID').default("").asString();
    public readonly githubOAuthClientSecret: string = env.get('GITHUB_OAUTH_CLIENT_SECRET').default("").asString();
    public readonly githubOAuthCallbackUrl: string = env.get('GITHUB_OAUTH_CALLBACK_URL').default("").asString();
    public readonly githubUrl: string = env.get('GITHUB_URL').default("github.com").asString();
    public readonly githubApiUrl: string = env.get('GITHUB_API_URL').default("api.github.com").asString();
    public readonly host: string = env.get('HOST').default("127.0.0.1").asString();
    public readonly port: number = env.get('PORT').default(9388).asPortNumber();
    public readonly concurrency: number = env.get('CONCURRENCY').default(10).asIntPositive();
    public readonly forceNoOpen: boolean = env.get('FORCE_NO_OPEN').default("false").asBool();
    public readonly noWarden: boolean = env.get('NO_WARDEN').default("false").asBool();
    public readonly forceHttps: boolean = env.get('FORCE_HTTPS').default("false").asBool() || this.enableRequestCertificate;
    public readonly failAttemptsToBan: number = env.get('FAIL_ATTEMPTS_TO_BAN').default(0).asIntPositive();
    public readonly failAttemptsDuration: number = env.get('FAIL_ATTEMPTS_DURATION').default(0).asIntPositive();
    public readonly requestRateLimit: number = env.get('REQUEST_RATE_LIMIT').default(0).asIntPositive();
    public readonly autoUpdateDuration: number = env.get('AUTO_UPDATE_DURATION').default(0).asIntPositive();
    public readonly lastActivityDays: number = env.get('LAST_ACTIVITY_DAYS').default(15).asIntPositive();

    // 开发变量
    public readonly sourceIpHeader: string = env.get('SOURCE_IP_HEADER').default("x-real-ip").asString();
    public readonly debug: boolean = env.get('DEBUG').default("false").asBool();
    public readonly disableAccessLog: boolean = env.get('DISABLE_ACCESS_LOG').default("false").asBool();

    public static readonly version: string = version;

    private constructor() { }

    public static getInstance(): Config {
        if (!Config.instance) {
            Config.init();
        }
        return Config.instance;
    }

    public get instance(): Config {
        return Config.instance;
    }

    public static init() {
        if (!Config.instance) {
            Config.instance = new Config();
            defaultInstance.RATE_LIMIT = Config.instance.requestRateLimit;
        }
    }
}

dotenv.config()