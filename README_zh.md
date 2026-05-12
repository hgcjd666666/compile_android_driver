# compile_android_driver

一键构建 Android 内核驱动模块（.ko），支持多 KMI 版本。

## 使用方法

### 1. 将你的驱动源码放入 `code/` 目录

```
code/
├── Makefile         # 标准内核外部模块 Makefile
├── your_driver.c    # 驱动源码
└── ...
```

Makefile 需遵循标准 Linux 内核外部模块格式：

```makefile
obj-m += your_driver.o

all:
    $(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
    $(MAKE) -C $(KDIR) M=$(PWD) clean
```

### 2. Push 到 GitHub，自动构建

往 `main`/`master` 分支推送 `code/` 下的变更后，GitHub Actions 会自动触发矩阵构建：

| KMI | Android 版本 | 内核版本 |
|---|---|---|
| `android12-5.10` | Android 12 | 5.10 |
| `android13-5.10` | Android 13 | 5.10 |
| `android13-5.15` | Android 13 | 5.15 |
| `android14-5.15` | Android 14 | 5.15 |
| `android14-6.1` | Android 14 | 6.1 |
| `android15-6.6` | Android 15 | 6.6 |
| `android16-6.12` | Android 16 | 6.12 |

构建产物会自动命名为 `<kmi>_<模块名>.ko`，如 `android14-6.1_your_driver.ko`，并上传为 Actions Artifact。

### 3. 手动触发

在 GitHub 仓库页面 → Actions → **Build LKM for Multiple KMI** → **Run workflow**，即可手动触发构建。

### 4. 下载产物

构建完成后，进入对应的 Action 运行记录，在 **Artifacts** 区域下载：
- 各 KMI 独立的 `.ko` 文件（按 KMI 版本分类）
- `all-modules` — 所有 KMI 的 `.ko` 打包为 ZIP

## 工作原理

利用 [ddk-min](https://github.com/ylarod/ddk-min) Docker 容器（预置对应版本的 GKI 内核源码和 LLVM/Clang 工具链），在内核源码树外通过标准 `make -C $(KDIR) M=$(PWD) modules` 机制编译内核模块。

## 目录结构

```
.
├── code/                     # 驱动源码目录（放你的 .c / Makefile）
├── .github/workflows/
│   ├── build-lkm.yml         # 矩阵构建入口（push / PR / 手动触发）
│   └── ddk-lkm.yml           # 实际构建逻辑（可被复用）
├── README.md
└── README_zh.md
```

## 本地构建

使用同样的 DDK 容器在本地编译：

```bash
# 以 android14-6.1 为例
docker run --rm -it -v $(pwd)/code:/workspace/module ghcr.io/ylarod/ddk-min:android14-6.1-20260313 bash -c "cd /workspace/module && make"
```

或者直接用本地内核源码树：

```bash
cd code
make KDIR=/path/to/your/kernel/src
```
