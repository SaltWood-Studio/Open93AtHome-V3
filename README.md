# Open93AtHome-V3

## 简介

这是一个类似于 [OpenBMCLAPI](https://github.com/bangbang93/openbmclapi) **主控端**的分发文件项目，经过三次重构，现已可以完美兼容 **Node、Python、C#、PHP** 端
> [!TIP]
> 本项目实际可被用于分发任何有效 Git 仓库内的文件，因此并不与 bangbang93HUB 有任何关联

## 主控部署

### Docker Compose 部署
``` shell
docker-compose up -d
```

### 手动部署

1. 安装 Node.js 环境
2. 克隆项目到本地
3. 安装依赖
``` shell
npm install
```
4. 编译项目
``` shell
npm run build
```
5. 启动项目
``` shell
node --enable-source-maps dist/index.js
```

## 节点部署

> [!IMPORTANT]
> 由于现在已有现成的修改端，因此本项目不再提供节点部署方式，请直接使用修改端进行节点部署
> 如实在有需要请自行摸索修改方式

## 调试

1. 将此项目 `git clone` 到本地
2. 使用**支持 Type Script 的 IDE** 打开项目
3. 愉快的开发吧🎉

``` shell
git clone https://github.com/SaltWood-Studio/Open93AtHome-V3.git
cd Open93AtHome-V3
```

### 贡献

提交 PR 前请确保你的代码至少经过编译测试

# 特别鸣谢

- **[openbmclapi](https://github.com/bangbang93/openbmclapi)**: 由 @bangbang93 大佬的项目获得了想法，诞生了此项目
- **[93AtHome-Dashboard](https://github.com/Mxmilu666/93Home-Dash)**: 由 @Mxmilu666 大佬为本项目编写的仪表盘
- **[bangbang93Hub](https://github.com/Mxmilu666/bangbang93HUB)**: 由 @Mxmilu666 大佬提出想法并付诸实践
- **[tianxiu2b2t](https://github.com/tianxiu2b2t)**: 帮助解决了 Avro 部分的问题，解答了一些弱智问题
