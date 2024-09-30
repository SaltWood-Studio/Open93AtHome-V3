import { Request, Response, NextFunction } from 'express';
import { Config } from './Config.js';

interface RateLimitRecord {
    tokens: number;        // 令牌数量
    lastRefill: number;    // 上次填充令牌的时间戳（毫秒）
    lastRequest: number;   // 最后一次请求的时间戳（用于清理过期记录）
}

class RateLimiter {
    private static instance: RateLimiter;
    private rateLimitMap: Map<string, RateLimitRecord>;
    public static RATE_LIMIT: number = 10;
    public static REFILL_INTERVAL: number = 1000;
    public static CLEANUP_INTERVAL: number = 60000;
    public static EXPIRATION_TIME: number = 300000;

    private constructor() {
        this.rateLimitMap = new Map();

        // 设置定期清理任务
        setInterval(this.cleanupRateLimitMap.bind(this), RateLimiter.CLEANUP_INTERVAL);
    }

    // 获取单例实例
    public static getInstance(): RateLimiter {
        if (!RateLimiter.instance) {
            RateLimiter.instance = new RateLimiter();
        }
        return RateLimiter.instance;
    }

    // 速率限制中间件
    public rateLimiterMiddleware(req: Request, res: Response, next: NextFunction): void {
        if (RateLimiter.RATE_LIMIT <= 0) {
            next(); // 速率限制功能关闭，直接处理请求
            return;
        }
        const ip = (req.headers[Config.getInstance().sourceIpHeader] as string) || req.ip; // 根据请求的IP地址进行限速
        if (!ip) throw new Error('No IP address provided.');
        const currentTime = Date.now();

        // 获取该IP地址的限速记录
        let record = this.rateLimitMap.get(ip);

        if (!record) {
            // 如果该IP地址没有记录，初始化令牌桶
            record = { tokens: RateLimiter.RATE_LIMIT, lastRefill: currentTime, lastRequest: currentTime };
            this.rateLimitMap.set(ip, record);
        }

        // 更新最后请求时间
        record.lastRequest = currentTime;

        // 计算自上次填充令牌后的时间间隔
        const timeSinceLastRefill = currentTime - record.lastRefill;

        // 根据时间间隔填充令牌桶
        if (timeSinceLastRefill > RateLimiter.REFILL_INTERVAL) {
            const tokensToAdd = Math.floor(timeSinceLastRefill / RateLimiter.REFILL_INTERVAL) * RateLimiter.RATE_LIMIT;
            record.tokens = Math.min(record.tokens + tokensToAdd, RateLimiter.RATE_LIMIT);
            record.lastRefill = currentTime;
        }

        // 判断令牌桶中是否还有令牌
        if (record.tokens > 0) {
            record.tokens--;  // 消耗一个令牌
            next();           // 继续处理请求
        } else {
            // 如果没有令牌了，返回429状态码 (Too Many Requests)
            res.status(429).send('Too Many Requests - try again later');
        }
    }

    // 清理超过过期时间的 IP 记录
    private cleanupRateLimitMap(): void {
        const currentTime = Date.now();
        this.rateLimitMap.forEach((record, ip) => {
            if (currentTime - record.lastRequest > RateLimiter.EXPIRATION_TIME) {
                this.rateLimitMap.delete(ip); // 移除过期记录
            }
        });
    }
}

// 导出单例实例的中间件方法
export const rateLimiter = RateLimiter.getInstance().rateLimiterMiddleware.bind(RateLimiter.getInstance());
export default RateLimiter;
