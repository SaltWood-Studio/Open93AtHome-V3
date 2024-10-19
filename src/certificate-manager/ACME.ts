import { Client } from 'acme-client';
import acme from 'acme-client';
import { Challenge } from 'acme-client/types/rfc8555.js';
import { DnsManager } from './DnsManager.js';
import { Config } from '../Config.js';
import { X509Certificate } from 'crypto';

export class ACME {
    private client: Client;
    private dnsManager: DnsManager;

    constructor(dnsManager: DnsManager, privateKey: acme.PrivateKeyBuffer) {
        this.dnsManager = dnsManager;

        // 初始化 ACME 客户端，使用 ZeroSSL 的 staging 环境测试
        this.client = new Client({
            directoryUrl: acme.directory.zerossl.production,
            accountKey: privateKey,
            externalAccountBinding: {
                kid: Config.instance.zerosslKid,
                hmacKey: Config.instance.zerosslHmacKey
            }
        });
    }

    public async registerAccount(email: string) {
        const account = await this.client.createAccount({
            contact: [`mailto:${email}`],
            termsOfServiceAgreed: true
        });
    }

    // 申请证书
    public async requestCertificate(domain: string, subDomain: string, email: string): Promise<[acme.PrivateKeyBuffer, acme.CsrBuffer, string, number, number]> {
        const [ key, csr ] = await acme.crypto.createCsr({
            altNames: [`${subDomain}.${domain}`]
        });
        const certificate = await this.client.auto({
            challengeCreateFn: async (authz: acme.Authorization, challenge: Challenge, keyAuthorization: string) => {
                if (challenge.type !== 'dns-01') {
                    throw new Error(`Unsupported challenge type: ${challenge.type}`);
                }
                const recordValue = keyAuthorization;
                this.dnsManager.addRecord(`_acme-challenge.${subDomain}`, recordValue, 'TXT');
            },
            challengeRemoveFn: async (authz: acme.Authorization, challenge: Challenge, keyAuthorization: string) => {
                if (challenge.type !== 'dns-01') {
                    throw new Error(`Unsupported challenge type: ${challenge.type}`);
                }
                this.dnsManager.removeRecord(`_acme-challenge.${subDomain}`, 'TXT');
            },
            csr,
            email,
            termsOfServiceAgreed: true,
            challengePriority: ['dns-01']
        });
        const x509cert = new X509Certificate(certificate);
        const validFrom = new Date(x509cert.validFrom).getTime();
        const expiresAt = new Date(x509cert.validTo).getTime();

        return [key, csr, certificate, validFrom, expiresAt];
    }
}
