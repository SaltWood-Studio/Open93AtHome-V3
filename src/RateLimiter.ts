import { Request, Response, NextFunction } from 'express';
import { Config } from './Config.js';
import { Utilities } from './Utilities.js';
import { NumberStorage } from './statistics/NumberStats.js';

interface RateLimitRecord {
    tokens: number;        // 令牌数量
    lastRefill: number;    // 上次填充令牌的时间戳（毫秒）
    lastRequest: number;   // 最后一次请求的时间戳（用于清理过期记录）
}

class RateLimiter {
    private rateLimitMap: Map<string, RateLimitRecord>;
    private static _rejectedRequest: NumberStorage | null = null;
    public RATE_LIMIT: number = 10;
    public REFILL_INTERVAL: number = 1000;
    public CLEANUP_INTERVAL: number = 60000;
    public EXPIRATION_TIME: number = 300000;

    public static get rejectedRequest(): NumberStorage {
        if (!RateLimiter._rejectedRequest) {
            RateLimiter._rejectedRequest = new NumberStorage('rejected_requests');
        }
        return RateLimiter._rejectedRequest;
    }

    public constructor() {
        this.rateLimitMap = new Map();

        // 设置定期清理任务
        setInterval(this.cleanupRateLimitMap.bind(this), this.CLEANUP_INTERVAL);
    }

    // 速率限制中间件
    public rateLimiterMiddleware(req: Request, res: Response, next: NextFunction): void {
        if (this.RATE_LIMIT <= 0) {
            next(); // 速率限制功能关闭，直接处理请求
            return;
        }
        const ip = (req.headers[Config.instance.dev.sourceIpHeader] as string).split(',')[0] || req.ip; // 根据请求的IP地址进行限速
        if (!ip) throw new Error('No IP address provided.');
        const currentTime = Utilities.getTimestamp();

        // 获取该IP地址的限速记录
        let record = this.rateLimitMap.get(ip);

        if (!record) {
            // 如果该IP地址没有记录，初始化令牌桶
            record = { tokens: this.RATE_LIMIT, lastRefill: currentTime, lastRequest: currentTime };
            this.rateLimitMap.set(ip, record);
        }

        // 更新最后请求时间
        record.lastRequest = currentTime;

        // 计算自上次填充令牌后的时间间隔
        const timeSinceLastRefill = currentTime - record.lastRefill;

        // 根据时间间隔填充令牌桶
        if (timeSinceLastRefill > this.REFILL_INTERVAL) {
            const tokensToAdd = Math.floor(timeSinceLastRefill / this.REFILL_INTERVAL) * this.RATE_LIMIT;
            record.tokens = Math.min(record.tokens + tokensToAdd, this.RATE_LIMIT);
            record.lastRefill = currentTime;
        }

        // 判断令牌桶中是否还有令牌
        if (record.tokens > 0) {
            record.tokens--;  // 消耗一个令牌
            next();           // 继续处理请求
        } else {
            RateLimiter.rejectedRequest.addData(1)
            // 如果没有令牌了，返回429状态码 (Too Many Requests)
            res.status(429).send('Too Many Requests - try again later');
        }
    }

    // 清理超过过期时间的 IP 记录
    private cleanupRateLimitMap(): void {
        const currentTime = Utilities.getTimestamp();
        this.rateLimitMap.forEach((record, ip) => {
            if (currentTime - record.lastRequest > this.EXPIRATION_TIME) {
                this.rateLimitMap.delete(ip); // 移除过期记录
            }
        });
    }
}

// 导出默认实例的中间件方法
export const defaultInstance = new RateLimiter();
export const rateLimiter = defaultInstance.rateLimiterMiddleware.bind(defaultInstance);
export default RateLimiter;