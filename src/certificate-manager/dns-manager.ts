export interface DnsManager {
    // 新版本中，Domain 将会放在实例里头，subDomain 更改为 recordName，但只是名字改了，丢到API的还是叫 subDomain
    // TTL 在实例里头

    addRecord(recordName: string, value: string, type: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<void>;
    removeRecord(recordName: string, type: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<void>;
    getRecords(): Promise<any[]>;
    getRecordByType(recordName: string, recordType: "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT"): Promise<any[]>;
}
