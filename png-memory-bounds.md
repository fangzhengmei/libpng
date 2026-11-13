# libpng 解码内存边界分析:行缓冲 × 辅助块解压 × 块缓存的联合作用

代码版本:本仓库(libpng 1.6.x,pnglibconf.h.prebuilt 默认配置)。
结论先行:**宽高限制、单块分配限制、块缓存计数是三条相互正交的防线,任意单独一条都堵不住资源耗尽**。默认配置下,一个 1×1 像素的 PNG 可以合法地让解码进程驻留约 8 GB 内存;而一张 100 万像素级的合法大图只需要几十 MB。必须三者联合收紧。

## 1. 三条独立的限制路径

### 1.1 宽高限制(只约束 IHDR 与行缓冲)

- 默认值:`PNG_USER_WIDTH_MAX = PNG_USER_HEIGHT_MAX = 1000000`(pnglibconf.h.prebuilt:214-215),运行期可用 `png_set_user_limits()` 调整(pngset.c:2008)。
- 生效点:`png_check_IHDR()`(png.c:1984、2006),超限即硬错误(`png_error`,"Image width/height exceeds user limit in IHDR"),在读取任何 IDAT 之前拒绝。
- 它实际约束的内存:
  - **行缓冲**:`png_read_start_row()`(pngrutil.c:4599)分配 `big_row_buf` 与 `big_prev_row` 各 `row_bytes + 48`,其中
    `row_bytes = PNG_ROWBYTES(max_pixel_depth, (width+7) & ~7) + 1 + pixel_slack`。
    最宽形态 RGBA16(`max_pixel_depth = 64`)下约为 `width × 8` 字节,两块合计 ≈ `width × 16` 字节。默认宽度上限 1,000,000 时约 16 MB,**与 height 无关**(libpng 逐行流式解码)。
  - **整图驻留(应用侧)**:若应用用 `png_read_png()` 一次性读入,图像内存 ∝ `width × height × 像素字节数`,这才是宽高限制真正封顶的大头。

### 1.2 单块分配限制(约束每个辅助块的压缩态与解压态)

- 默认值:`PNG_USER_CHUNK_MALLOC_MAX = 8000000`(pnglibconf.h.prebuilt:213),运行期 `png_set_chunk_malloc_max()`(pngset.c:2036);内部统一为 `png_chunk_max()`(pngpriv.h:900)。
- 生效点:
  - `png_read_buffer()`(pngrutil.c:376-381):任何辅助块读入缓冲区前,`new_size > png_chunk_max()` 直接返回 NULL,块被跳过。read_buffer 是**高水位复用**的,只增不减。
  - `png_decompress_chunk()`(pngrutil.c:668-686):zTXt/iTXt 的解压输出上限被钳到 `chunk_max − prefix − terminate`。即每个 zTXt/iTXt 无论压缩率多高,解压后最多 ~8 MB。解压是两遍式的:第一遍 `output = NULL` 只计量,然后 `png_malloc_base` 分配,第二遍真正解压——**瞬时峰值 = 压缩态 read_buffer(≤8 MB)+ 解压输出(≤8 MB)**。
  - iCCP:`png_icc_check_length()`(png.c:1578)用同一个 `png_chunk_max()` 拒绝超长 profile;且分配整个 profile 之前已先做 132 字节头校验和 tag 表校验(pngrutil.c:1387-1403),伪造的"大 profile"在分配前就被拦下。

### 1.3 块缓存计数(只数"块数",不数"字节")

- 默认值:`PNG_USER_CHUNK_CACHE_MAX = 1000`(pnglibconf.h.prebuilt:212),运行期 `png_set_chunk_cache_max()`(pngset.c:2026)。
- 生效点:tEXt(pngrutil.c:2381)、zTXt(pngrutil.c:2451)、iTXt(pngrutil.c:2567)、sPLT(pngrutil.c:1562)、待保存的未知块(pngrutil.c:3081)。每处理一块递减一次,耗尽后报 "no space in chunk cache"(benign error,跳块不中止)。
- 关键事实:**本版本 `png_handle_iCCP`(pngrutil.c:1320)不消耗 cache 计数**。iCCP 的驻留另有上界:新 profile 通过 `png_free_data(PNG_FREE_ICCP)` 释放旧的一份再"窃取"读缓冲(pngrutil.c:1456-1474),info 中永远只保留一份 ≤ chunk_max 的 profile。
- 文本块经 `png_set_text_2()`(pngset.c:952)**复制进 info_ptr,终身驻留**,直到 `png_destroy_read_struct()`。

## 2. 缺口:累计驻留 = cache_max × malloc_max,与尺寸限制无关

把三条路径叠在一起看:

| 内存项 | 上界 | 由谁约束 |
|---|---|---|
| 行缓冲 ×2 | ≈ width × 16 B | user_width_max |
| 整图像素(png_read_png) | width × height × 8 B | user_width/height_max |
| 单块瞬时(压缩态+解压态) | ≤ 2 × chunk_max ≈ 16 MB | chunk_malloc_max |
| **文本/辅助块累计驻留** | **≈ cache_max × chunk_max** | **两者乘积,无单一开关** |
| iCCP 驻留 | ≤ chunk_max(仅一份) | chunk_malloc_max |

缺口在于:cache 计数限制的是**块数**,malloc 限制的是**单块字节数**,没有任何机制限制**累计字节数**。默认值下累计文本驻留上界 = 1000 × 8 MB ≈ **8 GB**,而这条路径完全不经过 IHDR——**1×1 像素的文件即可触发,宽高限制形同虚设**。反过来,一张 100000×100000 的合法照片(行缓冲 ~1.6 MB,整图 ~80 GB 那是应用自己的选择)与辅助块毫无关系,若用"砍尺寸上限"来防内存,只会误伤合法大图,却放过了辅助块炸弹。

### 应拒绝的攻击输入 vs 合法大图

- **攻击特征**:IHDR 很小;IDAT 之前/之间塞大量 zTXt/iTXt(compression_flag=1)/tEXt 块;每块压缩数据极小( deflate 全零/重复内容,压缩率 >1000:1),解压后逼近 chunk_max。判别量:**辅助块数量多 × 单块解压后体积大 × 图像尺寸小**。
- **合法大图特征**:内存消耗集中在 IHDR 声明的像素数据上,辅助块少而小(真实 PNG 的文本块通常 < 几 KB,iCCP 通常 < 1 MB)。判别量:内存 ∝ width × height,而非 ∝ 块数。

## 3. 可构造的边界样本与实测结果

样本生成器(Python,deflate 全 'A' 负载)与读取 harness(可调三个限制、报告 getrusage 峰值 RSS)已实测:

| 样本 | 文件大小 | 限制设置 | 结果 |
|---|---|---|---|
| 1×1 + 1000 个 zTXt,每个 7.8 KB 压缩 → 7,999,000 B 解压 | 7.8 MB | **默认**(1000/8 MB/1e6×1e6) | **接受 998 块,峰值 RSS 7.81 GB** |
| 同上 | 7.8 MB | cache=32, malloc=1 MB | 全部拒收,文本 0 块,RSS 2 MB |
| 1×1 + 100 个 zTXt,每个 900 KB 解压 | 92 KB | cache=32, malloc=1 MB | 存 30 块后 "no space in chunk cache",RSS 30 MB |
| 1,000,000×1 RGBA16(合法宽图) | 35 KB | 默认 | 正常解码,RSS 25 MB(行缓冲 ×2 + 一行图像) |
| 同上 | 35 KB | width_max=100000 | 硬错误 "Invalid IHDR data",IHDR 阶段拒绝 |
| iCCP profile 7,999,000 B | 7.9 KB | 默认 | 头校验失败,benign 跳过,不驻留 |
| 同上 | 7.9 KB | malloc=1 MB | "profile too long",长度检查拒绝 |

攻击样本构造要点(zTXt 变体,iTXt 把 compression_flag 置 1 即可走同一 `png_decompress_chunk` 路径):

```
IHDR: 1×1, 8-bit gray           # 尺寸完全不设防
zTXt × N: key="k%06d" \0 \0 deflate("A" × 7999000)   # 每块 ~7.8 KB → ~8 MB
IDAT: 一行全零                   # 图像本身合法
IEND
```

N=1000 时恰好打满默认 cache 上限,累计 1000 × 8 MB ≈ 8 GB,而文件只有 7.8 MB——**放大系数约 1000 倍**,且每一步都在 libpng 自己的限制之内。

## 4. 可验证的拒绝策略

1. **三个限制必须同时设置**,使累计上界闭合:
   ```c
   png_set_user_limits(png, 32768, 32768);      /* 按业务最大图幅 */
   png_set_chunk_cache_max(png, 32);            /* 块数 */
   png_set_chunk_malloc_max(png, 1000000);      /* 单块字节 */
   ```
   此时文本累计驻留 ≤ 32 × 1 MB = 32 MB,行缓冲 ≤ 32768×16 ≈ 512 KB,单块瞬时 ≤ 2 MB,总上界可预测。
2. **不需要元数据的应用**可把 cache 压到 1(首个文本块即 benign 拒绝、不驻留),或注册未知块回调直接丢弃;iCCP 由长度+头校验兜底,无需额外处理。
3. **验证方法**:用第 3 节的 flood 样本跑 harness,观测 (a) 拒绝信号——stderr 出现 "no space in chunk cache" / "profile too long" / 硬错误 "Invalid IHDR data";(b) `getrusage(RUSAGE_SELF).ru_maxrss` 或 `/usr/bin/time -v` 的峰值 RSS 降到预算内。注意被拒的辅助块走 `png_chunk_benign_error`,默认只警告、跳块、继续解码——这是安全的降级;若应用调了 `png_set_benign_errors(png, 0)` 则升级为硬错误,两种模式都能阻断内存放大。
4. **不要用"限制图片尺寸"代替辅助块限制**:它约束的是 ∝width×height 的像素内存,对 1×1 + 文本洪泛完全无效;也不要只调 cache 或只调 malloc 之一——单独把 cache 降到 32 仍留 32×8 MB=256 MB,单独把 malloc 降到 1 MB 仍留 1000×1 MB=1 GB,只有乘积闭合后上界才真正可控。
