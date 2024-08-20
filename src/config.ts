import dotenv from 'dotenv'
import env from 'env-var'

export class Config {
    public static instance: Config

    public readonly githubOAuthClientId: string = env.get('GITHUB_OAUTH_CLIENT_ID').required().asString()
    public readonly githubOAuthClientSecret: string = env.get('GITHUB_OAUTH_CLIENT_SECRET').required().asString()
    public readonly githubOAuthCallbackUrl: string = env.get('GITHUB_OAUTH_CALLBACK_URL').required().asString()
    public readonly githubUrl: string = env.get('GITHUB_URL').default("github.com").asString()
    public readonly githubApiUrl: string = env.get('GITHUB_API_URL').default("api.github.com").asString()

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