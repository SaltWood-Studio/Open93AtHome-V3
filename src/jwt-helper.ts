import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken';
import { generateKeyPairSync, KeyObject } from 'crypto';

class JwtHelper {
    private static instance: JwtHelper;
    private readonly privateKey: KeyObject;
    private readonly publicKey: KeyObject;

    private constructor() {
        // 自动生成 RSA 密钥对
        const { privateKey, publicKey } = this.generateKeys();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    // 获取单例实例
    public static getInstance(): JwtHelper {
        if (!JwtHelper.instance) {
            JwtHelper.instance = new JwtHelper();
        }
        return JwtHelper.instance;
    }

    // 颁发JWT
    public issueToken(payload: object, audience: string, expiresInSeconds: number): string {
        // 自定义签名选项，允许覆盖默认的 expiresIn 和设置 audience
        const signOptions: SignOptions = {
            expiresIn: expiresInSeconds, // Token有效期，以秒为单位
            algorithm: 'RS256', // 使用 RSA 算法 (RS256)
            issuer: '93@Home-Center-Server', // 默认 issuer
            audience // 设置 audience
        };
        return jwt.sign(payload, this.privateKey, signOptions);
    }

    // 验证JWT
    public verifyToken(token: string): object | null {
        try {
            const decoded = jwt.verify(token, this.publicKey, {
                algorithms: ['RS256'],
            } as VerifyOptions);
            
            // 确保 decoded 是 object 类型
            if (typeof decoded === 'object' && decoded !== null) {
                return decoded;
            }

            return null;
        } catch (error) {
            console.error('JWT verification error:', (error as Error).message);
            return null;
        }
    }

    // 生成 RSA 公钥和私钥对
    private generateKeys(): { privateKey: KeyObject, publicKey: KeyObject } {
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048, // 密钥长度
        });
        return { privateKey, publicKey };
    }
}

export default JwtHelper;