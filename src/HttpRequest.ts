import got, { Got } from "got";
import { Config } from "./Config.js";
import os from "os";

export class HttpRequest {
    public static request: Got;
    
    public static init(): void {
        const appVersion = Config.version;
        const nodeVersion = process.version;
        const platform = os.platform();
        const release = os.release();
        const arch = os.arch();
        const locale = Intl.DateTimeFormat().resolvedOptions().locale;
                
        const userAgent = `Open93AtHome-Center/${appVersion} (Open93AtHome-Center; TypeScript; Node.js ${nodeVersion}; ${platform} ${release}, ${arch}; ${locale})`;

        HttpRequest.request = got.extend({
            retry: {
                limit: 1
            },
            headers: {
                'user-agent': userAgent
            }
        });
    }
}

export default HttpRequest;