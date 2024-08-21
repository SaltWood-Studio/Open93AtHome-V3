export class AvroEncoder {
    private byteStream: Uint8Array;

    constructor() {
        this.byteStream = new Uint8Array();
    }

    private static longToByte(value: number): Uint8Array {
        if (value < 0) {
            throw new Error("Negative values are not supported");
        }
        const o: number[] = [];
        let data = value;
        
        // Avoid generating excessively large arrays
        while (data > 0x7F) {
            o.push((data & 0x7F) | 0x80);
            data >>= 7;
        }
        o.push(data);
    
        // Create Uint8Array with exact length
        return new Uint8Array(o);
    }

    public setElements(count: number): void {
        this.setLong(count);
    }

    public setLong(value: number): void {
        const bytes = AvroEncoder.longToByte(value);
        this.byteStream = this.concatUint8Array(this.byteStream, bytes);
    }

    public setString(value: string): void {
        const bytes = new TextEncoder().encode(value);
        this.setLong(bytes.length);
        this.byteStream = this.concatUint8Array(this.byteStream, bytes);
    }

    public setBytes(value: Uint8Array): void {
        this.setLong(value.length);
        this.byteStream = this.concatUint8Array(this.byteStream, value);
    }

    public setEnd(): void {
        this.byteStream = this.concatUint8Array(this.byteStream, new Uint8Array([0x00]));
    }

    public getBytes(): Buffer {
        return Buffer.from(this.byteStream);
    }

    private concatUint8Array(a: Uint8Array, b: Uint8Array): Uint8Array {
        const c = new Uint8Array(a.length + b.length);
        c.set(a);
        c.set(b, a.length);
        return c;
    }
}
