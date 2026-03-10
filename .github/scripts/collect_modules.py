#!/usr/bin/env python3
# .github/scripts/collect_modules.py

import os
import sys
import re
import shutil
import argparse
from pathlib import Path
from typing import List, Set

def parse_makefile_for_modules(makefile_path: Path) -> Set[str]:
    """
    解析 Makefile，提取所有 obj-m += 指定的模块名（去掉 .o 后缀）。
    返回去重后的模块名集合。
    """
    modules: Set[str] = set()
    if not makefile_path.exists():
        print(f"Error: Makefile not found at {makefile_path}", file=sys.stderr)
        return modules

    content = makefile_path.read_text(encoding='utf-8', errors='ignore')
    # 按行处理，去除注释（以 # 开头的内容）
    for line in content.splitlines():
        # 去掉行内注释（从 # 到行尾）
        line = re.sub(r'#.*$', '', line).strip()
        if not line:
            continue
        # 匹配 obj-m += 模块列表
        if 'obj-m' in line and '+=' in line:
            parts = line.split('+=')
            if len(parts) < 2:
                continue
            # 右侧可能包含空格分隔的多个模块
            for token in parts[1].strip().split():
                token = token.strip()
                if not token:
                    continue
                # 如果以 .o 结尾，去掉 .o；否则保留原样（可能是模块名）
                if token.endswith('.o'):
                    token = token[:-2]
                modules.add(token)
    return modules

def find_ko_file(output_dir: Path, module_name: str) -> Path | None:
    """在输出目录中查找 module_name.ko 文件，返回第一个匹配的路径。"""
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file == f"{module_name}.ko":
                return Path(root) / file
    return None

def main():
    parser = argparse.ArgumentParser(description="Collect and rename kernel modules from build output.")
    parser.add_argument("--makefile-dir", required=True, help="Directory containing the Makefile (usually 'code')")
    parser.add_argument("--output-dir", required=True, help="Directory where built .ko files are located (e.g., workspace/exports)")
    parser.add_argument("--version-tag", required=True, help="Version tag to prepend to output filenames (e.g., android14-6.1)")
    parser.add_argument("--collect-dir", required=True, help="Directory where renamed modules will be stored")
    args = parser.parse_args()

    makefile_dir = Path(args.makefile_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    collect_dir = Path(args.collect_dir).resolve()
    version_tag = args.version_tag

    # 确保收集目录存在
    collect_dir.mkdir(parents=True, exist_ok=True)

    # 解析 Makefile 获取模块列表
    makefile_path = makefile_dir / "Makefile"
    modules = parse_makefile_for_modules(makefile_path)
    if not modules:
        print("No modules found in Makefile. Exiting.")
        sys.exit(0)

    print(f"Modules to collect: {', '.join(sorted(modules))}")

    found_any = False
    for mod in modules:
        ko_path = find_ko_file(output_dir, mod)
        if ko_path and ko_path.exists():
            dest_name = f"{version_tag}_{mod}.ko"
            dest_path = collect_dir / dest_name
            shutil.copy2(ko_path, dest_path)
            print(f"Copied: {ko_path} -> {dest_path}")
            found_any = True
        else:
            print(f"Warning: {mod}.ko not found under {output_dir}", file=sys.stderr)

    if not found_any:
        print("No kernel modules were found to collect.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()