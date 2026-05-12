# compile_android_driver

One-click build of Android kernel modules (.ko) for multiple KMI versions.

## Usage

### 1. Put your driver source in `code/` directory

```
code/
├── Makefile         # Standard kernel external module Makefile
├── your_driver.c    # Driver source
└── ...
```

Makefile should follow the standard Linux kernel external module format:

```makefile
obj-m += your_driver.o

all:
    $(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
    $(MAKE) -C $(KDIR) M=$(PWD) clean
```

### 2. Push to GitHub, auto-build

Push changes under `code/` to `main`/`master`, and GitHub Actions will automatically trigger a matrix build:

| KMI | Android | Kernel |
|---|---|---|
| `android12-5.10` | Android 12 | 5.10 |
| `android13-5.10` | Android 13 | 5.10 |
| `android13-5.15` | Android 13 | 5.15 |
| `android14-5.15` | Android 14 | 5.15 |
| `android14-6.1` | Android 14 | 6.1 |
| `android15-6.6` | Android 15 | 6.6 |
| `android16-6.12` | Android 16 | 6.12 |

Artifacts are named `<kmi>_<module_name>.ko`, e.g. `android14-6.1_your_driver.ko`.

### 3. Manual trigger

Go to GitHub → Actions → **Build LKM for Multiple KMI** → **Run workflow**.

### 4. Download artifacts

After build completes, download from the **Artifacts** section:
- Individual `.ko` files per KMI
- `all-modules` — ZIP archive of all KMIs

## How it works

Uses [ddk-min](https://github.com/ylarod/ddk-min) Docker containers (prebuilt with matching GKI kernel source and LLVM/Clang toolchain) to compile the module via standard `make -C $(KDIR) M=$(PWD) modules`.

## Directory Structure

```
.
├── code/                     # Driver source directory
├── .github/workflows/
│   ├── build-lkm.yml         # Matrix build entry (push / PR / manual)
│   └── ddk-lkm.yml           # Actual build logic (reusable)
├── README.md
└── README_zh.md
```

## Local Build

Using the same DDK container locally:

```bash
# Example for android14-6.1
docker run --rm -it -v $(pwd)/code:/workspace/module ghcr.io/ylarod/ddk-min:android14-6.1-20260313 bash -c "cd /workspace/module && make"
```

Or with a local kernel source tree:

```bash
cd code
make KDIR=/path/to/your/kernel/src
```
