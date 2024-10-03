import { Ignore, PrimaryKey, Table } from "../SQLiteHelper.js";

@Table("certificates", `
    clusterId TEXT NOT NULL PRIMARY KEY UNIQUE,
    key TEXT,
    csr TEXT,
    certificate TEXT,
    createdAt INTEGER NOT NULL
`)
@PrimaryKey("clusterId")
export class CertificateObject {
    public clusterId: string;

    public key: string;

    public csr: string;

    public certificate: string;

    public createdAt: number;

    public expiresAt: number;

    constructor() {
        this.clusterId = "";
        this.key = "";
        this.csr = "";
        this.certificate = "";
        this.createdAt = 0;
        this.expiresAt = 0;
    }

    public static create(clusterId: string, key: Buffer, csr: Buffer, certificate: string, expiresAt: number): CertificateObject {
        const obj = new CertificateObject();
        obj.clusterId = clusterId;
        obj.key = key.toString();
        obj.csr = csr.toString();
        obj.certificate = certificate;
        obj.createdAt = Date.now();
        obj.expiresAt = expiresAt;
        return obj;
    }
}