import { DnsManager } from './DnsManager.js';
import got from 'got';

export class CloudFlare implements DnsManager {
    private apiToken: string; // Cloudflare API Token
    private zoneId: string; // Cloudflare Zone ID
    private domain: string; // 域名
    private static TTL = 60; // 默认的 TTL

    constructor(apiToken: string, zoneId: string, domain: string) {
        this.apiToken = apiToken;
        this.zoneId = zoneId; // 将 zoneId 设置为实例属性
        this.domain = domain;
    }

    private async request(method: 'GET' | 'POST' | 'PUT' | 'DELETE', endpoint: string, data: Record<string, any> = {}): Promise<any> {
        const url = `https://api.cloudflare.com/client/v4${endpoint}`;

        console.log(`Cloudflare request: ${method} ${url}`);

        try {
            const response = await got(
                url,
                {
                    method,
                    headers: {
                        'authorization': `Bearer ${this.apiToken}`,
                        'content-type': 'application/json',
                    },
                    body: Object.keys(data).length ? JSON.stringify(data) : undefined
                }
            ).json<{ error: string, result: any }>();

            return response.result;
        } catch (error: any) {
            throw new Error(`Cloudflare request failed: ${error.message}`);
        }
    }

    public async addRecord(recordName: string, value: string, type: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<void> {
        const data = {
            type: type,
            name: `${recordName}.${this.domain}`,
            content: value,
            ttl: CloudFlare.TTL,
            proxied: false // 根据需求可以设置为 true 或 false
        };

        await this.request('POST', `/zones/${this.zoneId}/dns_records`, data);
    }

    public async modifyRecord(recordId: string, value: string, type: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<void> {
        const data = {
            type: type,
            content: value,
            ttl: CloudFlare.TTL,
            proxied: false // 根据需求可以设置为 true 或 false
        };

        await this.request('PUT', `/zones/${this.zoneId}/dns_records/${recordId}`, data);
    }

    public async removeRecord(recordName: string, type: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<void> {
        const records = await this.getRecords();
        const record = records.find((r: any) => r.name === `${recordName}.${this.domain}` && r.type === type);
        if (record) {
            await this.request('DELETE', `/zones/${this.zoneId}/dns_records/${record.id}`);
        } else {
            throw new Error(`No record found for ${recordName}`);
        }
    }

    public async getRecords(): Promise<any[]> {
        const records = await this.request('GET', `/zones/${this.zoneId}/dns_records`);
        return records; // 返回 DNS 记录列表
    }

    public async getRecordByType(recordName: string, recordType: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<any[]> {
        const records = await this.getRecords();
        return records.filter((record: any) => record.type === recordType && record.name === `${recordName}.${this.domain}`);
    }
}
