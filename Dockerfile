# 构建阶段
FROM alpine:latest AS build

RUN apk update && \
    apk add --no-cache \
    build-base \
    python3 \
    git \
    npm \
    openssh \
    nodejs

# 设置镜像源
# RUN npm config set registry https://registry.npmmirror.com

# 复制项目文件到容器中
WORKDIR /app
COPY . .

# 安装依赖并构建项目
RUN npm ci && \
    npm run build

# 运行阶段
FROM alpine:latest

# 仅安装运行时所需的包
RUN apk add --no-cache \
    nodejs \
    npm

WORKDIR /app

# 从构建阶段复制构建输出和依赖
COPY --from=build /app/dist /app/dist
COPY --from=build /app/node_modules /app/node_modules
COPY --from=build /app/package.json /app/package.json

# 启动应用程序
CMD ["node", "--enable-source-maps", "dist/index.js"]