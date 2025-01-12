import * as crypto from 'crypto';
import { DnsManager } from './DnsManager.js';
import got from 'got';

interface ApiResponse {
    Response: {
        Error: {
            Message: string;
        };
        RecordList: any[]
    };
}

export class DNSPod implements DnsManager {
    private secretId: string;
    private secretKey: string;
    private domain: string; // 新增 Domain 实例属性
    public static TTL = 600; // 这部分可以在实例化时提供，但在接口中未要求

    constructor(secretId: string, secretKey: string, domain: string) {
        this.secretId = secretId;
        this.secretKey = secretKey;
        this.domain = domain; // 将 domain 设置为实例属性
    }

    private async request(params: Record<string, any>) {
        const timestamp = Math.floor(Date.now() / 1000);
        params.SecretId = this.secretId;
        params.Timestamp = timestamp;
        params.Nonce = Math.floor(Math.random() * 10000);
        params.Version = '2021-03-23';

        const sortedParams = Object.keys(params)
            .sort()
            .map((key) => `${key}=${params[key]}`)
            .join('&');
        
        const signStr = `GETdnspod.tencentcloudapi.com/?${sortedParams}`;
        const signature = crypto.createHmac('sha1', this.secretKey).update(signStr).digest('base64');

        try {
            const response = await got('https://dnspod.tencentcloudapi.com/', {
                searchParams: {
                    ...params,
                    Signature: signature,
                },
            }).json<ApiResponse>();

            if (response.Response && response.Response.Error) {
                throw new Error(response.Response.Error.Message);
            }
            return response.Response;
        } catch (error: any) {
            throw new Error(`DNSPod request failed: ${error}`);
        }
    }

    public async addRecord(recordName: string, value: string, type: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<void> {
        try {
            const params = {
                Action: 'CreateRecord',
                Domain: this.domain,
                SubDomain: recordName, // 使用 recordName，API 仍需 subDomain
                RecordType: type,
                RecordLine: '默认',
                Value: value,
                TTL: DNSPod.TTL,
            };
            await this.request(params);
        } catch (error: any) {
            if (error.message.includes('already exists') || error.message.includes('已经存在')) {
                const records = await this.getRecords();
                const record = records.find((r: any) => r.Name === recordName && r.Type === type);
                console.log(`Record for ${recordName}.${this.domain} already exists, redirect to modification`);
                try { await this.modifyRecord(recordName, value, record.RecordId, type); } catch { }
            } else throw error;
        }
    }

    private async modifyRecord(recordName: string, value: string, recordId: any, type: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<void> {
        const params = {
            Action: 'ModifyRecord',
            Domain: this.domain,
            SubDomain: recordName,
            RecordType: type,
            RecordLine: '默认',
            RecordId: recordId,
            Value: value,
            TTL: DNSPod.TTL,
        };
        await this.request(params);
    }

    public async removeRecord(recordName: string, type: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<void> {
        const records = await this.getRecords();
        const record = records.find((r: any) => r.Name === recordName && r.Type === type);
        if (record) {
            const params = {
                Action: 'DeleteRecord',
                Domain: this.domain,
                RecordId: record.RecordId,
            };
            await this.request(params);
        } else {
            throw new Error(`No record found for ${recordName}.${this.domain}`);
        }
    }

    public async getRecords(): Promise<any[]> {
        const params = {
            Action: 'DescribeRecordList',
            Domain: this.domain
        };
        const response = await this.request(params);
        return response.RecordList;
    }

    public async getRecordByType(recordName: string, recordType: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<any[]> {
        const records = await this.getRecords();
        return records.filter((record: any) => record.type === recordType && record.Name === recordName);
    }
}
