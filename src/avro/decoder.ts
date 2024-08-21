export class AvroDecoder {
    private byteStream: ReadableStream<Uint8Array>;
    private reader: ReadableStreamDefaultReader<Uint8Array>;
    private buffer: Uint8Array;
    private bufferOffset: number;

    constructor(stream: ReadableStream<Uint8Array>) {
        this.byteStream = stream;
        this.reader = stream.getReader();
        this.buffer = new Uint8Array(0);
        this.bufferOffset = 0;
    }

    private async readBytes(length: number): Promise<Uint8Array> {
        let bytesRead = 0;
        let result = new Uint8Array(length);
        while (bytesRead < length) {
            if (this.bufferOffset >= this.buffer.length) {
                const { value, done } = await this.reader.read();
                if (done) throw new Error('Unexpected end of stream');
                this.buffer = value;
                this.bufferOffset = 0;
            }
            const bytesToCopy = Math.min(length - bytesRead, this.buffer.length - this.bufferOffset);
            result.set(this.buffer.slice(this.bufferOffset, this.bufferOffset + bytesToCopy), bytesRead);
            bytesRead += bytesToCopy;
            this.bufferOffset += bytesToCopy;
        }
        return result;
    }

    private async byteToLong(): Promise<number> {
        let shift = 0;
        let result = 0;
        let byte: number;

        do {
            byte = (await this.readBytes(1))[0];
            result |= (byte & 0x7F) << shift;
            shift += 7;
        } while ((byte & 0x80) !== 0);

        return (result >>> 1) ^ -(result & 1);
    }

    public async getElements(): Promise<number> {
        return this.getLong();
    }

    public async getLong(): Promise<number> {
        return this.byteToLong();
    }

    public async getString(): Promise<string> {
        const length = await this.byteToLong();
        const bytes = await this.readBytes(length);
        return new TextDecoder().decode(bytes);
    }

    public async getBytes(): Promise<Uint8Array> {
        const length = await this.byteToLong();
        return this.readBytes(length);
    }

    public async getEnd(): Promise<boolean> {
        const byte = (await this.readBytes(1))[0];
        return byte === 0x00;
    }
}
