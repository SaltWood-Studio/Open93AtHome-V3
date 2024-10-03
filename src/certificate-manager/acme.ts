import { Client, directory } from 'acme-client';
import acme from 'acme-client';
import { Challenge } from 'acme-client/types/rfc8555.js';
import { DnsManager } from './dns-manager.js';

export class ACME {
    private client: Client;
    private dnsManager: DnsManager;

    constructor(dnsManager: DnsManager, privateKey: acme.PrivateKeyBuffer) {
        this.dnsManager = dnsManager;

        // 初始化 ACME 客户端，使用 Let's Encrypt 的 staging 环境测试
        this.client = new Client({
            directoryUrl: directory.letsencrypt.production, // 换成 production 用于生产环境
            accountKey: privateKey
        });
    }

    // 注册账户并更新账户密钥
    public async registerAccount(email: string) {
        // 注册一个新的账户
        const account = await this.client.createAccount({
            contact: [`mailto:${email}`],
            termsOfServiceAgreed: true
        });
    }

    // 申请证书
    public async requestCertificate(domain: string, subDomain: string, email: string): Promise<[acme.PrivateKeyBuffer, acme.CsrBuffer, string, number]> {
        let [ key, csr ] = await acme.crypto.createCsr({
            altNames: [`${subDomain}.${domain}`]
        });
        let certificate;
        let expiresAt: number;
        try {
    
            // 1. 注册 ACME 账户
            console.log('Registering ACME account...');
            await this.registerAccount(email);
    
            // 2. 请求一个新的 ACME 订单
            console.log('Requesting a new ACME order...');
            let order = await this.client.createOrder({ identifiers: [{ type: 'dns', value: `${subDomain}.${domain}` }] });
            console.log('Order created:', order);
    
            // 3. 获取 Authorization 对象
            console.log('Getting authorization objects...');
            const authorizations = await this.client.getAuthorizations(order);
            const dnsAuthorization = authorizations[0]; // 选择第一个授权对象
            console.log('Authorization objects:', authorizations);
            console.log('Selected authorization object:', dnsAuthorization);
    
            // 4. 查找并准备 DNS-01 验证信息
            console.log('Preparing DNS-01 challenge...');
            const dnsChallenge = dnsAuthorization.challenges.find(
                (challenge: Challenge) => challenge.type === 'dns-01'
            );
            console.log('DNS-01 challenge:', dnsChallenge);
    
            if (!dnsChallenge) {
                throw new Error('DNS-01 challenge not found');
            }
    
            // 5. 生成 DNS TXT 记录值
            console.log('Generating DNS-01 challenge value...');
            const keyAuthorization = await this.client.getChallengeKeyAuthorization(dnsChallenge);
            const txtValue = keyAuthorization;
            console.log('DNS-01 challenge value:', txtValue);

            // 6. 添加 TXT 记录到 DNS
            console.log('Adding DNS-01 challenge record to DNS...');
            await this.dnsManager.addRecord(`_acme-challenge.${subDomain}`, txtValue, "TXT");
    
            // 7. 通知 ACME 服务器验证挑战
            console.log('Notifying ACME server of DNS-01 challenge...');
            await this.client.verifyChallenge(dnsAuthorization, dnsChallenge); // 添加 dnsAuthorization 参数
    
            // 8. 完成 ACME 挑战
            console.log('Completing ACME challenge...');
            await this.client.completeChallenge(dnsChallenge); // 添加 dnsAuthorization 参数
    
            // 9. 等待订单状态变为 "valid"
            console.log('Waiting for order to be valid...');
            order = await this.client.waitForValidStatus(order);
            console.log('Order is valid:', order);
            
            console.log('Finallize order:', order);
            order = await this.client.finalizeOrder(order, csr);
            console.log('Order finalized:', order);
            expiresAt = new Date(order.expires || Date.now()).getTime();
    
            // 10. 获取证书
            console.log('Getting certificate...');
            certificate = await this.client.getCertificate(order);
        }
        finally {
            // 11. 删除 DNS TXT 记录
            console.log('Removing DNS-01 challenge record from DNS...');
            await this.dnsManager.removeRecord(`_acme-challenge.${subDomain}`, "TXT");
        }

        return [key, csr, certificate, expiresAt];
    }
}
