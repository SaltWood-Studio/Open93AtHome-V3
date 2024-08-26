# 使用 Ubuntu 22.04 作为基础镜像
FROM ubuntu:24.04

# 安装 Node.js 和 npm
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_21.x | bash - && \
    apt-get install -y nodejs && \
    apt-get install -y build-essential python3 python3-pip

# 设置工作目录
WORKDIR /app

# 配置 NPM 使用 npmmirror 镜像加速
RUN npm config set registry https://registry.npmmirror.com

# 复制 package.json 和 package-lock.json（或 yarn.lock）到工作目录
COPY package*.json ./

# 安装项目依赖
RUN npm install

# 复制整个项目到工作目录
COPY . .

# 安装 TypeScript 编译器
RUN npm install -g typescript

# 编译 TypeScript 代码
# RUN tsc

# 设置启动命令
CMD ["npm", "run", "start"]
