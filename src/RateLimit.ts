import { Request, Response, NextFunction } from 'express';

interface RateLimitRecord {
    tokens: number;        // 令牌数量
    lastRefill: number;    // 上次填充令牌的时间戳（毫秒）
    lastRequest: number;   // 最后一次请求的时间戳（用于清理过期记录）
}

const rateLimitMap: Map<string, RateLimitRecord> = new Map();
const RATE_LIMIT = 10;        // 每秒允许的最大请求数
const REFILL_INTERVAL = 1000; // 令牌填充的时间间隔（毫秒）
const CLEANUP_INTERVAL = 60000; // 清理间隔（1分钟）
const EXPIRATION_TIME = 300000; // 记录过期时间（5分钟）

function rateLimiter(req: Request, res: Response, next: NextFunction) {
    const ip = req.ip; // 根据请求的IP地址进行限速
    if (!ip) throw new Error('No IP address provided.');
    const currentTime = Date.now();

    // 获取该IP地址的限速记录
    let record = rateLimitMap.get(ip);

    if (!record) {
        // 如果该IP地址没有记录，初始化令牌桶
        record = { tokens: RATE_LIMIT, lastRefill: currentTime, lastRequest: currentTime };
        rateLimitMap.set(ip, record);
    }

    // 更新最后请求时间
    record.lastRequest = currentTime;

    // 计算自上次填充令牌后的时间间隔
    const timeSinceLastRefill = currentTime - record.lastRefill;

    // 根据时间间隔填充令牌桶
    if (timeSinceLastRefill > REFILL_INTERVAL) {
        const tokensToAdd = Math.floor(timeSinceLastRefill / REFILL_INTERVAL) * RATE_LIMIT;
        record.tokens = Math.min(record.tokens + tokensToAdd, RATE_LIMIT);
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
function cleanupRateLimitMap() {
    const currentTime = Date.now();
    rateLimitMap.forEach((record, ip) => {
        if (currentTime - record.lastRequest > EXPIRATION_TIME) {
            rateLimitMap.delete(ip); // 移除过期记录
        }
    });
}

// 设置定期清理任务，每分钟执行一次
setInterval(cleanupRateLimitMap, CLEANUP_INTERVAL);

export default rateLimiter;
