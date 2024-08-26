# 使用 Node.js 21 官方镜像作为基础镜像
FROM node:21

# 安装构建工具
RUN apt-get update && \
    apt-get install -y build-essential python3

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

# 暴露应用的端口（如果有的话）
# EXPOSE 3000

# 设置启动命令
CMD ["npm", "run", "start"]
