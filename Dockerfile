# 使用Alpine Linux作为基础镜像
FROM alpine:latest

# 更改apk软件源为清华大学镜像并更新软件包
# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories
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

RUN rm -rf node_modules && \
    rm -rf dist && \
    npm install

# 安装TypeScript以及其他依赖包
RUN npm install -g typescript && npm install && npm run build

# 启动应用程序
CMD ["node", "dist/index.js"]