import dotenv from 'dotenv'
import env from 'env-var'
import { Utilities } from './utilities.js'

export class Config {
    public static instance: Config

    public readonly githubOAuthClientId: string = env.get('GITHUB_OAUTH_CLIENT_ID').required().asString()
    public readonly githubOAuthClientSecret: string = env.get('GITHUB_OAUTH_CLIENT_SECRET').required().asString()
    public readonly githubOAuthCallbackUrl: string = env.get('GITHUB_OAUTH_CALLBACK_URL').required().asString()
    public readonly githubUrl: string = env.get('GITHUB_URL').default("github.com").asString()
    public readonly githubApiUrl: string = env.get('GITHUB_API_URL').default("api.github.com").asString()
    public readonly statsDir: string = env.get('STATISTICS_DIRECTORY').default("./stats").asString()
    public readonly certificateDir: string = env.get('CERTIFICATE_DIRECTORY').default("./certificates").asString()
    public readonly port: number = env.get('PORT').default(9388).asPortNumber()
    public readonly adminToken: string = env.get('ADMIN_TOKEN').default(Utilities.generateRandomString(24)).asString()
    public static readonly version: string = "3.0.2";

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
        }
    }
}

dotenv.config()