#!/bin/bash

# 定义压缩包源文件路径
SOURCE_ZIP="/www/wwwroot/default/template.zip"

# 定义网站根目录的基础路径
WWWROOT_PATH="/www/wwwroot"

# 初始化解压计数器
UNZIPPED_COUNT=0

# 检查源压缩包是否存在
if [ ! -f "$SOURCE_ZIP" ]; then
  echo "错误：源压缩文件 $SOURCE_ZIP 不存在。"
  exit 1
fi

# 遍历所有网站根目录
for dir in $(ls -d "$WWWROOT_PATH"/*/); do
  # 排除掉作为源目录的 /wwwroot/default
  if [ "$(basename "$dir")" == "default" ]; then
    continue
  fi
  
  echo "--- 正在处理目录：$dir ---"

  # 检查目标网站根目录下是否存在 index.php 文件，如果存在则进行解压
  if [ -f "${dir}index.php" ]; then
    echo "  检测到网站根目录包含 index.php，开始解压..."
    # 解压文件到目标网站目录，并覆盖同名文件
    unzip -o "$SOURCE_ZIP" -d "$dir" > /dev/null
    
    # 检查解压是否成功
    if [ $? -eq 0 ]; then
      echo "  成功解压到 ${dir}"
      UNZIPPED_COUNT=$((UNZIPPED_COUNT + 1))
    else
      echo "  解压到 ${dir} 失败"
    fi
  else
    echo "  网站根目录不包含 index.php，跳过解压。"
  fi
done

# 输出最终统计结果
echo "------------------------------"
echo "脚本执行完毕。"
echo "共解压了 $UNZIPPED_COUNT 个网站。"
