import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken';
import { generateKeyPairSync, KeyObject, createPrivateKey, createPublicKey } from 'crypto';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import path from 'path';

class JwtHelper {
    private static _instance: JwtHelper;
    private readonly privateKey: KeyObject;
    private readonly publicKey: KeyObject;
    private static readonly privateKeyPath = path.resolve('./data', 'private.key');
    private static readonly publicKeyPath = path.resolve('./data', 'public.key');

    private constructor() {
        if (existsSync(JwtHelper.privateKeyPath) && existsSync(JwtHelper.publicKeyPath)) {
            // 如果密钥文件存在，读取它们
            this.privateKey = createPrivateKey(readFileSync(JwtHelper.privateKeyPath));
            this.publicKey = createPublicKey(readFileSync(JwtHelper.publicKeyPath));
        } else {
            // 如果密钥文件不存在，生成新的密钥对并保存
            const { privateKey, publicKey } = this.generateKeys();
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            
            // 保存密钥到本地文件
            writeFileSync(JwtHelper.privateKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
            writeFileSync(JwtHelper.publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }));
        }
    }

    public static get instance(): JwtHelper {
        return JwtHelper.getInstance();
    }

    // 获取单例实例
    public static getInstance(): JwtHelper {
        if (!JwtHelper._instance) {
            JwtHelper._instance = new JwtHelper();
        }
        return JwtHelper._instance;
    }

    // 颁发JWT
    public issueToken(payload: object, audience: string, expiresInSeconds: number): string {
        const signOptions: SignOptions = {
            expiresIn: expiresInSeconds,
            algorithm: 'RS256',
            issuer: '93@Home-Center-Server',
            audience,
        };
        return jwt.sign(payload, this.privateKey, signOptions);
    }

    // 验证JWT
    public verifyToken(token: string | undefined, audience: string | null = null): object | null {
        try {
            if (!token) return null;

            const decoded = jwt.verify(token, this.publicKey, {
                algorithms: ['RS256'],
                audience,
            } as VerifyOptions);
            
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
            modulusLength: 2048,
        });
        return { privateKey, publicKey };
    }
}

export default JwtHelper;