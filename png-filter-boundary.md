# PNG 解码防护诊断：行首滤波字节、截断行与滤波行长度边界

仓库：`/srv/fb2/fangzhengmei/0059-libpng-10-0181d793`（libpng 1.8.0.git，分支 `task/59`）
构建：CMake + gcc 13.3.0，x86-64，Linux 6.8；默认 `pnglibconf`（含 APNG、MNG features、progressive、SIMD 目标代码框架）
测试：本地构造 PNG（不读取任何外部输入），配合 ASan+UBSan 探针

---

## 0. 结论摘要

| 攻击面 | 当前行为 | 判定 |
| --- | --- | --- |
| 行首滤波字节取未知值（5..255） | 顺序/渐进两条路径都在**施加滤波之前**用 `bad adaptive filter value` 拒绝 | 安全（fail-closed） |
| 未知滤波字节出现在中间/末行/交错 pass | 同一位置拒绝；顺序读取能精确报告已完成的用户行数 | 安全 |
| 滤波行长度被宽度/位深/通道推到整数边界 | `rowbytes` 在 IHDR 阶段即被架构上限约束；`PNG_ROWBYTES` 在 `size_t` 下不溢出 | 安全 |
| bpp 与 rowbytes 的相对关系（`rowbytes == bpp`、`rowbytes` 为 `bpp` 整数倍、`rowbytes < bpp`） | `rowbytes == bpp` 与整数倍情形全部滤波可正确解码；`rowbytes < bpp` 在合法 IHDR 下**不可达**（`rowbytes = ceil(width*pixel_depth/8) ≥ bpp`） | 安全 |
| IDAT 截断（行数不足 / 行内字节不足） | **顺序读取报 `Not enough image data`；渐进读取静默成功** | **行为不一致（fail-open），见 §6.1** |
| 单行字节数为 2^32 或以上（`rowbytes + 1` 截断到 `uInt`） | 渐进读取把 `(rowbytes+1) mod 2^32` 当作一行的输出上限，**只写入极少数真实字节，其余用未初始化堆内容补齐后仍回调 `ok`** | **整数边界缺陷，见 §6.2** |
| 资源放大 | 默认 `PNG_USER_WIDTH_MAX=1000000` 下最坏约 16 MiB 行缓冲（实测 RSS ~10 MB）；提升到 `0x7fffffff` 后单行可达 17 GiB | 受用户限制约束（§7） |
| 越界读写 | 1300 次结构感知变异迭代（1700 次探针运行，含 ASan/UBSan）未发现越界 | 未发现 |

一句话结论：**滤波字节与本仓库内的行长度计算没有可利用的越界**；真正需要修的是「渐进读取器把截断流当成功」和「`uInt` 截断导致渐进读取器交付未写入的行」这两个 fail-open 问题。

---

## 1. 诊断方法与隔离

所有测试工件都在**独立目录**中，避免工具链从数据目录加载代码：

```
/tmp/59-scripts/        脚本与探针（pnggen*.py, fuzz.py, pngprobe.c, impprobe.c）
/tmp/59-data/           生成/变异的 PNG（含 REFS.txt / REFS2.txt 参考行）
/tmp/lp-build/          普通构建（无 sanitizer）
/tmp/lp-asan/           ASan+UBSan 构建
/tmp/lp-test/           上游 ctest 构建
```

- 数据生成：`python3 -I`（隔离模式）运行，从不 `cd` 进入数据目录执行解释器。
- 探针 `pngprobe.c` 有四种读法：`seq`（`png_read_info`+`png_read_update_info`+逐行 `png_read_row`）、`prog`（`png_set_progressive_read_fn` + 1/3/16 字节不规则喂数据）、`info`（仅 IHDR 阶段）、`readpng`（`png_read_png` 全图 API）。
- ASan/UBSan 探针返回：`RESULT ok|error`、`ERR <libpng 消息>`、`WARN n`、`ROWS_DONE n`（顺序读取已完成行数）、`CALLBACKS n` / `ENDED n`（渐进读取行回调/结束回调次数）。

---

## 2. IHDR 字段校验（解码的第一道闸门）

### 2.1 调用链

```
png_read_info() -> png_read_chunk_header() -> png_handle_chunk()
    -> read_chunks[] 表（长度/位置/重复性检查，pngrutil.c:3164 起）
    -> png_handle_IHDR()            pngrutil.c:889
         读取 13 字节，字段装入 png_ptr；先算 pixel_depth/rowbytes（pngrutil.c:953）
    -> png_set_IHDR()               pngset.c:426
    -> png_check_IHDR()             png.c:1933   <- 全部语义校验在这里
```

`png_handle_IHDR` 会**先**写 `png_ptr->rowbytes = PNG_ROWBYTES(pixel_depth, width)`（pngrutil.c:953），然后才调用校验。这个顺序是安全的，因为紧随其后的 `png_set_IHDR`→`png_check_IHDR` 一旦发现任何非法值就 `png_error`，没有任何路径能在校验失败后继续使用这个 `rowbytes`。

### 2.2 校验项与实测拒绝位置

| IHDR 字段 | 校验位置 | 条件 | 实测错误串 |
| --- | --- | --- | --- |
| width | png.c:1941 | `== 0` | `Image width is zero in IHDR` → `Invalid IHDR data` |
| width | png.c:1947 | `> PNG_UINT_31_MAX` | 实际更早被 `png_get_uint_31` 拒绝：`PNG unsigned integer out of range` |
| width | png.c:1961 | 架构上限（见 §5.1） | `Image width is too large for this architecture` |
| width | png.c:1984 | `> user_width_max`（默认 1000000） | `Image width exceeds user limit in IHDR` |
| height | png.c:1993/1999/2006 | 同上四项 | `Image height is zero/Invalid image height/...exceeds user limit` |
| bit_depth | png.c:2016 | 非 {1,2,4,8,16} | `Invalid bit depth in IHDR` |
| color_type | png.c:2023 | `==1, ==5, >6` | `Invalid color type in IHDR` |
| 组合 | png.c:2030 | palette 且 depth>8；RGB/GA/RGBA 且 depth<8 | `Invalid color type/bit depth combination in IHDR` |
| interlace | png.c:2039 | `>= PNG_INTERLACE_LAST` | `Unknown interlace method in IHDR` |
| compression | png.c:2045 | `!= 0` | `Unknown compression method in IHDR` |
| filter method | png.c:2065/2085 | `!= 0`（MNG 64 仅在特定条件下允许，且本调用序列因有 PNG 签名必定拒绝） | `Unknown filter method in IHDR` + `Invalid filter method in IHDR` |
| 汇总 | png.c:2093 | 任一置位 | `Invalid IHDR data` |

被拒样本（`REFS.txt` 中 `REF=ERROR` 的 38 个非法样本；`seq` 全部 38 个 fatal，`prog` 24 个 fatal、14 个被 §6.1 放行）实测：

```
ihdr_w0.png             WARN Image width is zero in IHDR            -> Invalid IHDR data
ihdr_h0.png             WARN Image height is zero in IHDR           -> Invalid IHDR data
ihdr_w_2e31.png         ERR  PNG unsigned integer out of range
ihdr_bd3.png            WARN Invalid bit depth ... / Invalid color type/bit depth ... -> Invalid IHDR
ihdr_ct1/ct5.png        WARN Invalid color type in IHDR             -> Invalid IHDR data
ihdr_pal16.png          WARN Invalid color type/bit depth combination -> Invalid IHDR data
ihdr_gray16_2.png       WARN Invalid color type/bit depth combination -> Invalid IHDR data
ihdr_il2.png            WARN Unknown interlace method in IHDR       -> Invalid IHDR data
ihdr_comp1.png          WARN Unknown compression method in IHDR      -> Invalid IHDR data
ihdr_fm1/fm64.png       WARN Unknown filter method / Invalid filter method -> Invalid IHDR data
ihdr_w_1000001.png      WARN Image width exceeds user limit in IHDR  -> Invalid IHDR data
ihdr_h_1000001.png      WARN Image height exceeds user limit in IHDR -> Invalid IHDR data
ihdr_len12.png          ERR  IHDR: too short                        （顺序读取，表驱动）
ihdr_len14.png          ERR  IHDR: too long                         （顺序读取，表驱动）
ihdr_duplicate.png      ERR  IHDR: out of place
ihdr_missing.png        ERR  IDAT: Missing IHDR before IDAT
```

注意：渐进读取器对 IHDR 长度用的是另一条旧路径 `Invalid IHDR length`（pngpread.c:344 附近），与顺序读取的表驱动消息不同——只是消息文本差异，都是 fatal error。

### 2.3 与滤波相关的两个字段

- **interlace 为 2..254** 会在 IHDR 阶段就被拒，因此 `png_read_start_row` 里 `png_pass_inc[png_ptr->pass]` 永远只在 0..6 索引；交错行长度不会拿到越界表项。
- **filter method（IHDR 字节 11）≠ 0** 被拒。注意它与「行首自适应滤波字节」是两回事：前者是 IHDR 的 compression/filter method 字段，后者是每条扫描线第一个字节。恶意样本可以 IHDR 合法（filter method=0）但对某些行写入 5..255 的滤波字节，这落在 §4。

---

## 3. 行缓冲分配（`png_read_start_row`）

`pngrutil.c:4599`。关键顺序：

```
4599  png_read_start_row()
4606  png_init_read_transformations()
4608  interlaced ? 用 pass 表算 num_rows/iwidth : num_rows=height, iwidth=width
4630  max_pixel_depth = pixel_depth（再按 PACK/EXPAND/EXPAND_16/FILLER/GRAY_TO_RGB/USER_TRANSFORM 提升）
4776  png_ptr->maximum_pixel_depth = (png_byte)max_pixel_depth
4782  row_bytes = (width + 7) & ~7             // 对齐到 8 像素
4786  row_bytes = PNG_ROWBYTES(max_pixel_depth, row_bytes) + 1 + ((max_pixel_depth+7)>>3)
4794  if (row_bytes + 48 > old_big_row_buf_size) 重新分配
4801     png_calloc(row_bytes + 48)   // 交错时清零
4805     png_malloc(row_bytes + 48)   // 非交错
4807     png_malloc(row_bytes + 48)   // big_prev_row
4827  else: row_buf  = big_row_buf + 31
4830       prev_row = big_prev_row + 31
4835  旧 PNG_MAX_MALLOC_64K 构建：rowbytes > 65535 时报错
4839  if (png_ptr->rowbytes > PNG_SIZE_MAX - 1) png_error("Row has too many bytes to allocate in memory")
4842  memset(prev_row, 0, rowbytes + 1)
4873  flags |= PNG_FLAG_ROW_INIT
```

### 3.1 为什么「+48 / +31」是安全的

- 真实需要的跨度是 `[row_buf, row_buf + 1 + rowbytes)`，其中 +1 是滤波字节。
- `row_bytes` 至少是 `PNG_ROWBYTES(max_pixel_depth, 对齐宽度) + 1 + ceil(max_pixel_depth/8)`，分配量是 `row_bytes + 48`。
- 非对齐分支（`PNG_TARGET_ROW_ALIGNMENT == 1`，本构建）：`row_buf = base + 31`，于是写入区间是 `[base+31, base+31+rowbytes]`，**前缀 31 字节、后缀 17 字节**。
- 16 字节对齐分支：`row_buf = base + 32 - extra - 1`，`extra = (base+32) & 0x0f ∈ [0,15]`，所以 `row_buf ∈ [base+16, base+31]`，**前缀 ≥16、后缀 ≥16**。这样 `row_buf+1`（首个像素字节）对齐到 16 字节边界，符合注释 pngrutil.c:4810-4821 的说明。

### 3.2 `prev_row` 清零与滤波预测源

`memset(prev_row, 0, rowbytes + 1)`（pngrutil.c:4842）保证第一行的 `Up/Average/Paeth` 预测器读到的是 0，不会读未初始化内存。交错图像每进入新 pass 时 `png_read_finish_row` 再次清零（pngrutil.c:4562 / pngpread.c:1045）。

### 3.3 `iwidth` 与「对齐宽度」

- 分配用的是**对齐后**的 `width`（`(width+7) & ~7`），并按 `maximum_pixel_depth`（可能被变换提升到 64）计算，因此分配总是 ≥ 实际需要的 `PNG_ROWBYTES(pixel_depth, iwidth) + 1`。交错各 pass 的 `iwidth ≤ width`。
- 实测极端宽度（每行 65535/65536 字节，以及 8192×16bit RGBA=65536 字节）都正常解码，且 65536 字节行（跨 64 KiB 边界）在**非** `PNG_MAX_MALLOC_64K` 构建下成功——见 §5.3。

---

## 4. 滤波分派与未知类型

### 4.1 分派点（两条并行代码路径）

顺序读取 `pngread.c:534-545`：

```c
png_ptr->row_buf[0] = 255;                       /* 535：无数据时强制报错 */
png_read_IDAT_data(png_ptr, png_ptr->row_buf, row_info.rowbytes + 1);   /* 536 */
if (png_ptr->row_buf[0] > PNG_FILTER_VALUE_NONE) {   /* 538 */
   if (png_ptr->row_buf[0] < PNG_FILTER_VALUE_LAST)  /* 540 */
      png_read_filter_row(png_ptr, &row_info, row_buf+1, prev_row+1, row_buf[0]);
   else
      png_error(png_ptr, "bad adaptive filter value");     /* 544 */
}
```

渐进读取 `pngpread.c:818-824`：同样的 `>0 && <PNG_FILTER_VALUE_LAST` 判断，之后 `png_error(png_ptr, "bad adaptive filter value")`（pngpread.c:823）。**与顺序读取的差别**：渐进路径没有 `row_buf[0] = 255` 的预置，因为它只在 `avail_out == 0`（整行填满）时才进入 `png_push_process_row`。

真正的函数表分派在 `png_read_filter_row`（pngrutil.c:4319）：

```c
if (filter > PNG_FILTER_VALUE_NONE && filter < PNG_FILTER_VALUE_LAST) {
   if (pp->read_filter[0] == NULL) png_init_filter_functions(pp);
   pp->read_filter[filter-1](row_info, row, prev_row);
}
```

三重防护：

1. `row_buf[0] = 255` 预置（**仅顺序读取**）；若 IDAT 一个字节都没产出，`255` 落入 `>= LAST` 分支，报 `bad adaptive filter value`，而不是静默使用垃圾值。但实测 `short_empty_idat.png` 在达到该分支前就在 zlib 层失败（`Not enough image data`），因为 `png_read_IDAT_data` 的 `avail_out` 检查先触发。渐进读取没有这个预置，靠「只在整行填满时才处理」来保证 `row_buf[0]` 是 IDAT 里的真实字节。
2. `filter < PNG_FILTER_VALUE_LAST`（=5）的上界比较在**索引 `read_filter[filter-1]` 之前**完成，`read_filter` 数组只有 `PNG_FILTER_VALUE_LAST-1 = 4` 个元素（pngstruct.h:453），因此不可能越界索引。
3. 表项函数自身是 C 实现；`PNG_TARGET_IMPLEMENTS_FILTERS` 只覆盖 bpp==3/4 的 Sub/Avg/Paeth（intel/intel_init.c:30-40 等），且仍以 `row_info->rowbytes` 为循环上界。

### 4.2 未知滤波字节实测

| 样本 | 位置 | seq | prog |
| --- | --- | --- | --- |
| `badfilter_5/6/127/128/254/255.png` | 第 0 行 | `ERR bad adaptive filter value`, ROWS_DONE 0 | `ERR bad adaptive filter value` |
| `badfilter_lastrow_5.png` | 末行 | `ERR ...`, ROWS_DONE 2 | `ERR ...` |
| `badfilter_final_row4png.png` | 第 3 行（共 4 行） | `ERR ...`, ROWS_DONE 3 | `ERR ...` |
| `badfilter_interlaced_pass1.png` | Adam7 pass 1 首行 | `ERR ...`, ROWS_DONE 4 | `ERR ...` |
| `badfilter_first_pal.png` | 调色板图首行 | `ERR ...` | `ERR ...` |
| `frameshift_missing_filter.png` | 行错位后 | `ERR bad adaptive filter value` | — |
| `frameshift_short_middle.png` | 行错位后 | `ERR bad adaptive filter value` | — |

所有样本在 fatal error 路径上终止（默认 error_fn 触发 longjmp），`row_buf` 未被用于滤波，`prev_row` 未被覆写。**没有出现「未知类型被当作 NONE 静默通过」的情形。**

### 4.3 合法滤波的像素核对

447 个合法样本（`ok_*`、`okil_*`、`min_*`、`extra_idat`，来自 `REFS.txt`；另有 `bnd_*` 306 个与 `big_*` 120 个）逐行比对 Python 参考实现（独立实现 Sub/Up/Avg/Paeth 与 Adam7 采样）：

- 顺序读取 894/894 行集完全一致（REFS.txt：447 个样本 × 2 种读法）。
- 渐进读取 894/894 行集完全一致（在应用按契约于 `info_fn` 调 `png_read_update_info` 之后）。
- 306 个「字节边界」样本（宽度取使 `width*bit_depth` 刚好落在 8 的整数倍前后 ±2，覆盖全部 15 种合法彩色类型/位深组合 × 非交错/Adam7）：

```
boundary cases: 306
seq + prog: ok 612, bad 0
```

- 大宽度样本（1000/8191/8192/8193/10000，含 65528/65536 字节行）：

```
checked 120 bad 0 nonok 0    (seq 与 prog 的 RESULT 与逐行字节完全一致)
```

这确认了：宽度/位深把行长度推到整数边界（`rowbytes == bpp`、`(width+7)&~7` 对齐、跨 64 KiB、跨 2 的幂）时，`bpp` 与 `rowbytes` 的计算与滤波实现是一致的，不会因「最后字节不满」而误写。

### 4.4 `rowbytes == bpp` 与 `rowbytes < bpp`

- 滤波函数的 `bpp = (pixel_depth + 7) >> 3`：当 `pixel_depth` 为 8 的倍数时 `bpp = pixel_depth/8`；当 `pixel_depth < 8`（1/2/4 位）时 `bpp = 1`。
- 因为 `rowbytes = ceil(width * pixel_depth / 8)` 且 `width ≥ 1`，所以恒有 `rowbytes ≥ bpp`。取等的情形是 `width == 1`，或子字节位深下恰好一字节（如 1 位宽 1..8）。实测（16bit RGBA，bpp=8，宽度 1..5，全部用 Paeth）：
  - `rb8_bd16ct6_w1.png`：`rowbytes = bpp = 8` —— `png_read_filter_row_avg` 的 `istop = rowbytes - bpp = 0`（pngrutil.c:4168）与 `paeth_multibyte` 的 `rp_end += rowbytes - bpp`（pngrutil.c:4255）都退化为空循环，结果 `ROW 1 07090b0d0f111315` 正确。
  - 宽度 2/3/4/5（`rowbytes` 16/24/32/40，均为 `bpp` 的整数倍）同样正确。
- 因此「`rowbytes` 是 `bpp` 的整数倍」这一常见边界（每次复用行缓冲跨度）不会让 Paeth/Avg 的指针算术出现负增量。

### 4.5 截断行在滤波分派层的表现

- 行内字节不足 → zlib 层先失败（顺序读取 `Not enough image data`，pngrutil.c:4364/4369/4393/4496）。
- 只缺滤波字节（`short_missing_filter_byte.png`，行字节数恰好等于 `rowbytes`）→ 顺序读取在 `png_read_IDAT_data` 里发现 `avail_out` 未清零而报 `Not enough image data`（ROWS_DONE 0）。
- 行长度完全正确但滤波字节是 5..255 → §4.2 的 `bad adaptive filter value`。

结论：**截断行不会绕过滤波分派**；但渐进读取器对「流提前结束」的处理是完全另一回事，见 §6.1。

---

## 5. bpp / rowbytes 计算的溢出边界

### 5.1 IHDR 阶段的架构上限（防溢出的核心）

`png.c:1961`：

```c
if (((width + 7) & ~(png_alloc_size_t)7) >
    (((PNG_SIZE_MAX - 48 - 1) / 8) - 1))
   -> "Image width is too large for this architecture"
```

设计意图（注释 png.c:1968-1978）：用「1 字节/像素的最坏情形 ×8（64 位/像素）」来保守约束，使得 `png_read_start_row` 的任何 `+48 / +1 / 额外像素` 运算都不可能在 `size_t` 上回绕。`png_alloc_size_t` 是 `size_t`（pngconf.h:445 起，除非 `PNG_SMALL_SIZE_T`）。

- 64 位：`PNG_SIZE_MAX = 2^64-1`，该不等式对任何 `width ≤ 2^31-1` 都成立 → 架构检查不触发（实测 `MAXW=0x7fffffff` 时上表所有位深都能通过 IHDR，被接受的宽度上限恒为 `0x7fffffff`，即被 `PNG_UINT_31_MAX` 与用户限制共同限制）。
- 32 位：`(2^32-49)/8 - 1 = 536870903`；`(width+7)&~7 ≤ 536870904` → 宽度上限 536870904（模型计算，见下表）。这是**唯一的宽度硬上限来源**；用户限制（默认 1e6）通常先命中。

模型（`PNG_ROWBYTES` + start_row 加法在 32 位 `size_t` 上的最坏值）：

| pixel_depth | 最大宽度 | rowbytes | rowbytes + 1 + 像素 | + 48 |
| --- | --- | --- | --- | --- |
| 1 | 536870904 | 67108863 | 67108865 | 67108913 |
| 8 | 536870904 | 536870904 | 536870906 | 536870954 |
| 16 | 536870904 | 1073741808 | 1073741810 | 1073741858 |
| 32 | 536870904 | 2147483616 | 2147483618 | 2147483666 |
| 64 | 536870904 | 4294967232 | 4294967234 | 4294967282 |

全部 ≤ 2^32-1，因此 32 位上不会溢出。

> **边界声明**：以上为按 `png.c:1961` 公式做的离线计算；本机为 64 位环境，无法实际驱动 32 位的架构拒绝分支（无 `-m32` 运行时：安装缺 `Scrt1.o`/`crti.o`，见 §10）。所以「32 位上 `Image width is too large for this architecture` 会在 `png_read_start_row` 之前生效」这一条是**代码+算术**结论，不是实测结论。

### 5.2 `PNG_ROWBYTES` 本身

`pngpriv.h:526`：

```c
#define PNG_ROWBYTES(pixel_bits, width) \
   ((pixel_bits) >= 8 ? (size_t)(width) * (((size_t)(pixel_bits)) >> 3) \
                      : ((((size_t)(width) * (size_t)(pixel_bits)) + 7) >> 3))
```

- `pixel_bits` 在 `png_row_info`/`png_struct` 里是 `png_byte`（0..255，实际 ≤ 64）。
- 所有正常调用点的 `width` 都是 `png_uint_32`（≤ 2^31-1），在 64 位 `size_t` 下乘积最多 `2^31 × 8 = 2^34`，不会溢出。
- `png_read_start_row` 的 `PNG_ROWBYTES(max_pixel_depth, row_bytes)`（pngrutil.c:4786）参数 `row_bytes = (width+7)&~7 ≤ 2^31+8`、`max_pixel_depth ≤ 64`，结果 ≤ 2^34。安全。
- `PNG_ROWBYTES` 的 `+ 7` 在 `pixel_bits < 8` 分支里作用于已经乘过的结果；`width × pixel_bits ≤ 2^31 × 7 < 2^35`，同样不溢出。
- 32 位 `size_t` 下 `width × 8` 会到 2^34 而溢出——**这正是 `png.c:1961` 的架构上限存在的原因**：它保证被接受的 `width` 使 `(width+7)&~7` ≤ `(2^32-49)/8 - 1`，从而 `pixel_bits=64` 时乘积 < 2^32。

> **正确性交叉核对**：`png.c:1961` 的上限用的是 `PNG_SIZE_MAX` 与「8 字节/像素」的保守组合，而实际 `max_pixel_depth` 最大也是 64（8 字节），所以该上限在 32 位上恰好覆盖最坏情形，不会出现「通过 IHDR 但 `PNG_ROWBYTES` 溢出」的窗口。

### 5.3 行字节跨 64 KiB / 2^31 / 2^32 实测

| 场景 | 结果 |
| --- | --- |
| `rb65535_g8.png`（65535 字节行） | `RESULT ok`，1 行正确 |
| `rb65536_g8.png`（65536 字节行） | `RESULT ok` |
| `rb65536_rgba16.png`（8192×RGBA16 = 65536） | `RESULT ok` |
| `ihdr_w_max31.png`（w=2^31-1, RGB8, rowbytes 6.4 GB） | 默认限制下 IHDR 阶段拒绝；`MAXLIMITS` 下 `png_read_start_row` 分配失败 → `ERR Out of memory`（把 `ulimit -v` 设为 500 MB 时确认是 libpng 自己报的 OOM，而不是进程被杀） |
| `ihdr_w_max31_16rgba.png`（rowbytes 17 GiB） | 同上 |
| `wrap_4GiB_row.png`（w=2^29, RGBA16, rowbytes=2^32） | 顺序：`ERR Not enough image data`；渐进：`RESULT ok` + 行回调 2 次，交付内容大半是未初始化堆数据（见 §6.2） |

`PNG_MAX_MALLOC_64K` 分支（pngrutil.c:4789/4835）只在 16 位/分段寻址的遗留构建里生效；本构建未定义该宏，因此 65536 字节行成功——这与 1.6.43 系统库行为一致。

### 5.4 `png_combine_row` 的边界

`pngrutil.c:3400` 起，交错展开时用 `transformed_pixel_depth` 与 `png_ptr->width`：

- `info_rowbytes` 双检（pngrutil.c:3422）：`png_combine_row` 内再算一次 `PNG_ROWBYTES(pixel_depth, row_width)` 与 `info_rowbytes` 比对，不一致立即 `internal row size calculation error`。这挡住了「应用声明了错误的变换尺寸」导致的写入越界。
- `end_ptr = dp + PNG_ROWBYTES(pixel_depth, row_width) - 1`（pngrutil.c:3438）：`row_width == 0` 时有前置检查（pngrutil.c:3428 `internal row width error`）；`row_width ≥ 1` 时长度 ≥ 1，不会算出 `dp - 1`。
- `pixel_depth & 7 != 0` 时（用户变换给了非 8 倍数的深度）报 `invalid user transform pixel depth`（pngrutil.c:3651），避免「按字节复制」假设被破坏。

---

## 6. 交错行处理路径与两处 fail-open 缺陷

### 6.1 截断流：顺序拒绝 vs 渐进放行

**现象**（对照 `REFS.txt` 中 `REF=ERROR` 的截断样本）：

```
文件                           seq                                  prog
short_ct0_bd1_cut1.png        error Not enough image data           ok  (WARN 0, CALLBACKS 3/4)
short_ct0_bd8_cut1.png        error Not enough image data           ok
short_ct2_bd8_cut1/2/5.png    error Not enough image data           ok
short_ct6_bd16_cut1/2/5.png   error Not enough image data           ok
short_interlaced_cut2.png     error Not enough image data (31 行)    ok
short_missing_filter_byte.png error Not enough image data           ok (CALLBACKS 1/2)
silent_partial_lastrow.png    error Not enough image data (2 行)     ok (CALLBACKS 2/4, 后 2 行全零)
cleanrows_k1.png              error Not enough image data           ok (CALLBACKS 1/3)
cleanrows_k2.png              error Not enough image data           ok (CALLBACKS 2/3)
```

**代码路径**：顺序读取在 `png_read_IDAT_data` 末尾检查 `avail_out > 0` 就 `png_error("Not enough image data")`（pngrutil.c:4496 附近）。渐进读取的 `png_process_IDAT_data`（pngpread.c:684 起）在 `Z_STREAM_END` 时只做：

```c
png_ptr->mode |= PNG_AFTER_IDAT;
png_ptr->flags |= PNG_FLAG_ZSTREAM_ENDED;
if (zstream.avail_in > 0 || idat_size > 0) png_chunk_benign_error("Extra compressed data");
break;
```

它**没有**「`avail_out > 0` 却遇到 `Z_STREAM_END` → 数据不足」的检查。于是：

1. 已完整的行照常回调；
2. 未完整的行（`avail_out` 未清零）被丢弃，不回调（实测 `CALLBACKS` 少于 `height`）；
3. 随后读到 IEND，`png_push_have_end` 正常触发 → 应用看到「成功 + 结束回调」。

行只有在 `avail_out == 0`（即整行填满）时才进入 `png_push_process_row`（pngpread.c:788-789），因此**部分行本身不会被交付**；缺陷是「少交付若干行，却报成功」。用 `MALLOC_PERTURB_=171`（未写入字节为 `0x54`）复核：

```
silent_partial_lastrow.png  prog: RESULT ok / CALLBACKS 2 / ENDED 1 / height=4
                                  HEAD 01020304f16b2a0b      <- 只有 2 个完整行，均为真实数据
silent_misframe_g1.png      prog: RESULT ok / CALLBACKS 3 / ENDED 1 / height=4
                                  HEAD 000b16                 <- 3 行真实数据，第 4 行（半行）被丢弃
                                                              （数据流 7 字节 / 每行 2 字节 / height=4）
short_ct0_bd1_cut1.png      prog: RESULT ok / CALLBACKS 3 / ENDED 1 / height=4
short_missing_filter_byte   prog: RESULT ok / CALLBACKS 1 / ENDED 1 / height=2
```

`short_ct0_bd1_cut1.png` 的 `HEAD aa805500aa80` 里出现的 `0xaa` 不是填充值，而是 IDAT 解压后的真实载荷（`00 aa80 | 01 55ab | 02 5580`，前 3 行完整）；用不同填充值（`MALLOC_PERTURB_=0x55` → `0xaa`）复核，三个样本的 `HEAD` 内容不随填充值改变，确认交付的都是真实数据，没有未初始化字节混入。

真正的「旧内容混入」只发生在 §6.2 的 `uInt` 截断情形——那里 `avail_out` 被设得比真实行跨度小，于是「填满一行」的判断在只写入少数字节后就成立，`png_push_process_row` 随即以 `row_info->rowbytes`（真实跨度）为界做滤波与 `memcpy(prev_row, ...)`（pngpread.c:831），把未写入的部分补齐。这与 §6.1 是两回事，且 §6.1 的修复不能消除 §6.2。

**风险**：越界读写没有（`row_buf` 分配 ≥ `rowbytes+1`，滤波只写 `[0, rowbytes)`，且部分行不进入滤波）。但这是**完整性/可用性**缺陷：
- 应用无法区分「流截断」与「图像只有这么高」——`png_get_current_row_number` 停在 `num_rows-1` 而 `num_rows` 仍按 IHDR 的 `height` 报告；
- 输出的行集不完整，缺的行不会被任何错误信号标记（缩略图、OCR、指纹、去重都会静默使用残缺内容）；
- 与顺序读取器行为不一致，攻击者可以构造同一文件在两种 API 下得到不同结果（绕过去重/校验层）。

**最小修复**（改 `pngpread.c` 的 `Z_STREAM_END` 分支即可，不触及滤波）。要点是：`Z_STREAM_END` 只说明**这一段** IDAT 的 deflate 流结束了，后面可能还有别的 IDAT 块，也可能真的是流结尾。因此不能在 `Z_STREAM_END` 当场就判定「数据不足」（合法文件常有多个 IDAT 块，第一个块的 deflate 流独立结束）。正确的位置是**确定不会再有 IDAT 时**——即 `png_push_read_chunk` 读到非 IDAT 块（pngpread.c:582-594）那一刻：

```c
/* pngpread.c, png_push_read_IDAT 的「下一个块不是 IDAT」分支 */
{
   png_ptr->process_mode = PNG_READ_CHUNK_MODE;

   if ((png_ptr->flags & PNG_FLAG_ZSTREAM_ENDED) == 0)
      png_error(png_ptr, "Not enough compressed data");   /* 现有检查 */

   /* NEW: deflate 流结束了，但最后一行没填满 -> 图像不完整 */
   if (png_ptr->zstream.avail_out > 0 &&
       (png_ptr->row_number < png_ptr->num_rows || png_ptr->pass <= 6))
      png_error(png_ptr, "Not enough image data");
}
```

这个位置天然避开了 `png_process_data_pause` 的语义问题：暂停只是 `png_process_data` 提前返回，`process_mode` 仍是 `PNG_READ_IDAT_MODE`，不会走到这个分支。需要在库内确认的边界：

- `avail_out > 0` 且行已全部读完（`row_number == num_rows` 且 `pass > 6`）时是合法的「流末尾有空闲 padding」，不能报错——条件的后半句就是为此。
- APNG 的 `fdAT` 帧走另一条分支：`png_ptr->num_frames_read > 0` 时，非 `fdAT` 块进入 pngpread.c:550-578；其中「`ZSTREAM_ENDED` 已置位」的分支（pngpread.c:554-561）直接调 `frame_end_fn` 并返回，**没有任何行完整性检查**；只有 `chunk_name == png_IEND` 且流未结束时才报 `Not enough image data`（pngpread.c:568）。APNG 帧的 fail-open 需要单独补检查（可用 `info_ptr->next_frame_height` 作为该帧应有的行数）。
- `png_set_benign_errors(png_ptr, 1)` 不影响这里——用的是 `png_error` 而非 `png_benign_error`，与顺序读取器一致。

> 兼容性说明：这与 1.6.43 系统库行为一致（用系统库 `libpng16.a` 跑同一套样本，`ACCEPTED(bad)` 同样是那 14 个文件）。所以这是一处**长期存在、两条读取路径不对称**的行为，而不是本仓库引入的回归。

### 6.2 `uInt` 截断：`rowbytes + 1` 在 4 GiB 边界

渐进读取在设置输出缓冲时对**已经加 1 的行跨度**做 `uInt` 转换（三处：`png_push_read_chunk` 的 pngpread.c:379-381、`png_process_IDAT_data` 的 pngpread.c:723-725、APNG 复位的 pngrutil.c:4937-4938）：

```c
png_ptr->zstream.avail_out = (uInt)(PNG_ROWBYTES(png_ptr->pixel_depth,
                                                png_ptr->iwidth) + 1);
```

`avail_out` 是 zlib 的 `uInt`（32 位）。`(rowbytes + 1) mod 2^32` 决定库只要求 zlib 产出多少字节，而这个值可能远小于真实行跨度：

| rowbytes | 真实跨度 rowbytes+1 | `avail_out` | 实测样本 | 结果 |
| --- | --- | --- | --- | --- |
| 0xFFFFFFFF | 2^32 | **0** | `wrap_avail0.png`（w=1431655765, RGB8） | `prog`: `ERR Decompression error in IDAT`（zlib 对 `avail_out==0` 返回错误，运气好） |
| 0x100000000 | 2^32+1 | **1** | `wrap_4GiB_row.png`（w=2^29, RGBA16） | `prog`: **`RESULT ok`，回传 2 行，内容全为 `0x54` 填充值** |
| 0x100000005 | 2^32+6 | **6** | `wrap_avail6.png`（w=1431655767, RGB8） | `prog`: **`RESULT ok`，回传 2 行；每行前 6 字节来自 IDAT（`1111111111` + 1 字节滤波），其后全是填充值** |

三种情形的共同点是：`avail_out` 一旦小于真实行跨度，zlib 每次只填 `avail_out` 字节就报「输出已满」，`png_process_IDAT_data` 据此认为「产生了一行」（pngpread.c:788-789 的 `avail_out == 0 → png_push_process_row`），而这一行在 `row_buf` 里只被写入极少数真实字节。补齐其余部分的是 `png_push_process_row` 里的 `png_read_filter_row`：它对 `row_info->rowbytes` 字节做滤波，但 `row_info->rowbytes` 仍由 64 位计算得出（真实跨度），所以它读写的仍是完整的分配区——**没有越界，只是数据来源是未初始化/上一行残留的堆内容**。

更糟的副作用是**行数按 `floor(解压字节数 / avail_out)` 计算**，于是比真实应得的行数多出 `2^32 / avail_out` 倍。实测 `wrap_avail6_h64.png`（w=1431655767, RGB8, height=64, 压缩文件仅 **71 字节**）：

```
prog: RESULT ok / CALLBACKS 9 / ENDED 1 / INFO height=64 rowbytes=4294967301
      MALLOC_PERTURB_=0x55: CB1 first8=1111111111aaaaaa, CB2..CB9 first8=0000000000aaaaaa
seq : RESULT error / ERR Not enough image data / ROWS_DONE 0
```

一个 71 字节的文件让应用回调 9 次，每次都是「5 字节攻击者数据 + 4 GiB 未初始化堆」；应用若对每行做哈希/转码/上传，成本与暴露量都是 9×4 GiB 量级，而库报告成功。

**实测输出**（`MALLOC_PERTURB_=171` 时 glibc 的 malloc 填充为 `0x54`，用于区分「库写入」与「未写入」；`HEAD` 采样的是回调收到的 `row`，即 `row_buf+1` 载荷起点）：

```
wrap_4GiB_row.png (rowbytes=2^32, avail_out=1)
  seq  : RESULT error / ERR Not enough image data / ROWS_DONE 0
  prog : RESULT ok / CALLBACKS 2 / ENDED 1
         HEAD 54545454545454545454545454545454     <- 库从未写入

wrap_avail6.png (rowbytes=2^32+5, avail_out=6)
  seq  : RESULT error / ERR Not enough image data / ROWS_DONE 0
  prog : RESULT ok / CALLBACKS 2 / ENDED 1
         HEAD 11111111115454540000000000545454
         PERROW (MALLOC_PERTURB_=0x55 -> 填充 0xaa）
           CB 1 y0 first8=1111111111 aaaaaa     <- 5 个真实载荷字节，其后填充
           CB 2 y1 first8=0000000000 aaaaaa     <- 5 个真实字节，其后填充
```

`HEAD` 是行回调收到的字节串接前 16 字节。填充模式随 `MALLOC_PERTURB_` 变化（`0x54`/`0xaa`），说明**库把未初始化堆内容当作像素交给了应用**，同时报告成功。库自身无越界读写（`row_buf` 按 `rowbytes + 48` 分配，`big_row_buf` + `big_prev_row` 各一份，实测 RSS 峰值约 8.4 GB），风险落在**应用层**：应用会把这段内存写进输出图片、缩略图、哈希或网络响应（信息泄露 / 指纹污染），且完全没有信号可以检测。

**可达性**：

- `png_read_start_row` 在该尺寸下能成功分配（64 位 `PNG_ROWBYTES` ≤ 2^37 不溢出，`png_malloc_base` 只校验 `> PNG_SIZE_MAX`）。
- 默认 `PNG_USER_WIDTH_MAX = 1000000`：最大 `rowbytes = 1000000 × 8 B = 8 MB < 2^32`，**默认配置不可达**。但 `png_set_user_limits(png, 0x7fffffff, ...)` 是文档化的合法用法（pngset.c:2008-2023 明确说「要接受任意尺寸就把两个限制设成 0x7fffffff」），而 2^32 行只需 width ≥ 2^28（16bit RGBA）或 ≥ 2^30（RGB8），**都超过默认 1e6**。所以这是「应用主动放宽尺寸限制」组合下的缺陷。
- 32 位架构上 `PNG_ROWBYTES` 返回值 ≤ 4294967282（§5.1 表），`+1` ≤ 4294967283 < 2^32，**32 位不会截断**。缺陷只在 64 位 + 放宽限制时可达。

> 更正记录：初稿曾写「`rowbytes == 0x100000000` 截断为 0」。实际是 `(rowbytes+1) mod 2^32 = 1`；`avail_out == 0` 只发生在 `rowbytes == 0xFFFFFFFF`。表格与实测输出已按真实值修正。

**最小修复**（优先改共用点，使两条读取路径一致）：

```c
/* pngrutil.c png_read_start_row，紧接现有的 PNG_SIZE_MAX 检查之后 */
if (png_ptr->rowbytes >= (png_alloc_size_t)((uInt)-1))   /* == ZLIB_IO_MAX */
   png_error(png_ptr, "Row too large for this build");
```

这一条同时覆盖 `rowbytes == 0xFFFFFFFF`（`rowbytes+1` 溢出为 0）与 `>= 0x100000000`（`+1` 截断），且：
- 默认限制（8 MB）下完全不可触发，不改变任何合法行为；
- 顺序读取本来就会在 `Not enough image data` 处失败，因此对顺序路径只是把「晚失败」提前为「早失败」；
- `PNG_MAX_MALLOC_64K` 构建早已在 65535 处更严格地拒绝。

如果只想改渐进路径（最小 diff），则在上述三处（pngpread.c:379-381、723-725，pngrutil.c:4937-4938）把 `(uInt)(rb + 1)` 换成带检查的版本；但三处容易漏改，且 `png_push_process_row` 的 `memcpy(prev_row, row_buf, rowbytes+1)`（pngpread.c:831）仍会以 64 位跨度读写——既然分配足够，这仍是安全的，只是行内容不可信。

**另需一并修的语义问题**：即使 `avail_out` 正确，渐进读取器在 `Z_STREAM_END` 时也不检查「已产出行数 < num_rows」（§6.1）。§6.2 的样本之所以能「成功」，一半原因是 §6.1 的放行。两处应一起修。

### 6.3 交错路径本身

- 每条 pass 进入时 `png_read_finish_row` 会重算 `iwidth`/`num_rows` 并清零 `prev_row`（pngrutil.c:4562-4588；渐进版 pngpread.c:1030-1075）。`iwidth` 的除法用 pass 表的 `png_pass_inc`/`png_pass_start`，索引始终在 0..6（因为 IHDR 的 interlace 字段已被 §2 限制）。
- `iwidth` 可以等于 0（某些 pass 对小图完全没有采样点）：`png_read_finish_row` 的 `do/while` 循环（pngrutil.c:4587）会跳过 `iwidth == 0` 的 pass，不会生成空行读取。
- 实测 324 个交错样本（宽度 1,2,3,4,5,7,8,9,17 × 9 种彩色/位深组合 × 4 种滤波器组合）在 seq/prog 下都 `RESULT ok` 且与参考行一致。
- 实测 `padbits_il_bd1_pad0/pad1.png`（Adam7 1 位图，每 pass 末字节填充位分别为 0/1）：两条路径解码结果**完全相同**（`ROW 0 40 / ROW 1 a0 / ROW 2 40`），说明 `png_combine_row` 的「保留最后字节未用位」逻辑（pngrutil.c:3434 `end_mask = (pixel_depth * row_width) & 7` 与 3879-3881 的恢复）在交错展开时正确工作。

---

## 7. 资源放大评估

| 场景 | 输入大小 | 峰值内存/时间 | 说明 |
| --- | --- | --- | --- |
| `amp_w1e6_rgba16.png`（默认限制内，1e6×1, RGBA16，rowbytes=8 MB） | 66 B | RSS ~10 MB，<0.01 s | 行缓冲 2×8 MB |
| `rb65536_rgba16.png` | 142 B | RSS 2.3 MB | 正常 |
| `amp_1e6x1e6_g8.png` / `amp_1e6x1e6_g8_66b.png` + `png_read_png` | 66 B | RSS 4.0 GB，3.8 s | 全图 API 为 1e6 行 × 1 MB 行分配 |
| `amp_1e6x1e6_g8.png` + `png_image_begin_read`/`finish_read` | 66 B | 立即拒绝 | 简化 API 的 `image too large`（32 位尺寸检查 pngread.c:4258-4287） |
| `amp_2GiB_row.png`（MAXLIMITS，rowbytes 2 GiB） | 66 B | RSS 2.1 GB，1.2 s | `big_row_buf`+`big_prev_row`+`memset` |
| `wrap_4GiB_row.png`（MAXLIMITS，rowbytes 4 GiB） | 66 B | RSS ~8.4 GB | 两份 4 GiB 缓冲 |
| `wrap_avail6_h64.png`（MAXLIMITS，rowbytes 2^32+5，height 64） | **71 B** | RSS 8.4 GB，7.9 s，回调 9 行 | 每 6 字节解压数据被计为 1 行；库报 ok |
| `wrap_avail6_big.png`（MAXLIMITS，rowbytes 2^32+5，18.7 MB 压缩） | 18.7 MB | RSS 4.2 GB，3.1 s，**1,606,439 条警告** | §6.2 截断 + 警告放大叠加 |
| `surplus_bomb_8MiB.png`（前 2 行合法 + 8 MiB 多余解压数据） | 8.2 KB | RSS 2.3 MB | `Too much image data` 警告后立即丢弃多余数据；**不解压放大** |
| `short_ct2_bd8_cut1.png` 等截断样本 | 小 | 小 | 顺序读取失败退出 |

要点：

- **放大只与 IHDR 声明的尺寸线性相关**，与压缩比无关：libpng 每次只申请「一行 + 固定 padding」，多余解压数据会被 `Too much image data` 丢弃（pngrutil.c:4471/4499）而不继续写入。8 MiB 的无用解压数据没有导致任何额外分配。
- **默认配置的实际上界**：`PNG_USER_WIDTH_MAX=PNG_USER_HEIGHT_MAX=1e6`。单行最大 = 1e6 × 64 bit = 8 MB，两份 `big_row_buf`/`big_prev_row` 合计 ~16 MB（实测 `def_w1e6_rgba16_trunc.png` 的 RSS 峰值 ~10 MB，`def_w1e6_g8_trunc.png` ~3.2 MB）。`png_read_png`（全图）上限 = 1e6 × 8 MB = 8 TB 尝试 → `png_malloc` 失败并 `Out of memory`（实测 1e6×1e6 灰度图 4 GB RSS 后失败），即**兜底是 OOM 而非越界**；`png_image` 简化 API 则在 32 位尺寸检查处提前拒绝。
- **把限制抬到 `0x7fffffff` 后**：单行可达 17 GiB（§5.3 表），`png_read_png` 可达无法表示的尺寸。文档（`png_set_user_limits`，pngset.c:2008-2023）明确「设为 0x7fffffff 可接受任意尺寸」，所以调用方要自负其责；但 §6.2 表明渐进读取在这种尺寸下**语义已经错了**（不是慢，而是静默交付未写入数据）。
- 渐进读取的**警告放大**：`surplus_bomb_8MiB.png` 以 1 字节粒度喂入时产生 **8148 条** `Extra compression data in IDAT` 警告（每次 `png_process_IDAT_data` 调用一条，pngpread.c:776）。按字节喂数据的应用（网络流常见）会被日志淹没，且 `warn_fn` 若做 I/O 会放大成本。同一份数据顺序读取只有 1 条警告。建议在渐进路径对该警告做「一次性」抑制（类似 `PNG_FLAG_ZSTREAM_ENDED` 已置位时不再重复告警）。
- **两个缺陷叠加后的最坏组合**（`wrap_avail6_big.png`：w=1431655767, RGB8, rowbytes=2^32+5，18.7 MB 压缩输入，`avail_out` 被截断为 6）：第一行只吃进 6 字节，其余 4 GiB 解压数据全部落进「多余数据」分支，产生 **1,606,439 条警告**、耗时 3.1 s、RSS 4.2 GB。压缩输入可以任意大（这里 18.7 MB 已很温和），警告条数随「输入字节数 × 喂入粒度」增长。这不是解压炸弹（内存与声明尺寸而非压缩比相关），但是**日志/CPU 放大**，且完全由 §6.2 的截断触发。

---

## 8. 越界读写风险评估

**未发现越界读写。** 依据：

1. 447 个合法样本 + 306 个字节边界样本 + 120 个大宽度样本在 ASan+UBSan 下零报告。
2. 5 组结构感知变异模糊测试（变异 IHDR 字段、IDAT 内滤波字节、截断/复制/拆分 IDAT、位翻转），共 1300 次变异迭代；400 次跑 `seq`+`prog` 双路径（800 次探针运行），900 次跑 `seq`（900 次），合计 1700 次探针运行：

```
iterations 400 crashes 0   (both -> 800 runs)
iterations 300 crashes 0   (seq, seed 1)
iterations 300 crashes 0   (seq, seed 2)
iterations 300 crashes 0   (seq, seed 3)
```

3. 三处关键的「长度到指针」转换都有前置校验：
   - 滤波表索引：`filter < PNG_FILTER_VALUE_LAST`（pngrutil.c:4322）
   - 行缓冲跨度：`rowbytes > PNG_SIZE_MAX - 1` 拒绝（pngrutil.c:4839），分配 `rowbytes + 48` 且 `row_buf` 前置 31 字节
   - 交错写入目标：`info_rowbytes` 双检 + `row_width == 0` 拒绝 + `pixel_depth & 7` 拒绝（pngrutil.c:3422/3428/3651）
4. 滤波函数自身只以 `row_info->rowbytes` 为界（`istop = row_info->rowbytes`，pngrutil.c:4131；`rp_end = row + row_info->rowbytes`，pngrutil.c:4191/4255），`row` 由 `png_ptr->row_buf + 1` 传入，跨度正好是 `[1, 1+rowbytes)` ⊂ 分配区。

**残余风险（非内存安全）**：
- §6.1 的静默截断 → 完整性/一致性。
- §6.2 的部分写入行交付 → **把未初始化的堆内存当作像素交给应用**（应用层的泄露/污染面，而不是 libpng 的缓冲区越界；libpng 自身读写的仍是已分配区间）。在放宽尺寸限制的 64 位部署中这值得按漏洞处理。
- §7 的警告放大 → 日志型 DoS。
- `png_read_png` 全图分配 → OOM 型 DoS（有上限、可被应用规避）。

---

## 9. 最小修复建议（按优先级）

1. **（高）渐进读取器：确定不会再有 IDAT 时，若最后一行没填满，必须失败而不是成功。**
   - 位置：`png_push_read_IDAT` 的「下一个块不是 IDAT」分支（pngpread.c:582-594）；不要放在 `Z_STREAM_END` 处，因为合法的多 IDAT 文件里第一个块的 deflate 流会独立结束（详见 §6.1）。
   - 做法：在现有的「`ZSTREAM_ENDED` 未置位 → 报 error」检查之后，增加 `avail_out > 0 && (row_number < num_rows || pass <= 6)` → `png_error("Not enough image data")`。该点不在 `png_process_data_pause` 的路径上（暂停时 `process_mode` 仍是 `PNG_READ_IDAT_MODE`），因此不会误报合法的分段喂入。
   - 另需同样处理 APNG 的 `num_frames_read > 0` 分支（pngpread.c:554-561）。
   - 回归：§10 的 T1–T5。

2. **（高）渐进读取器：拒绝 `rowbytes + 1` 无法用 `uInt` 表示的行。**
   - 位置：pngpread.c:379-381、pngpread.c:723-725、pngrutil.c:4937-4938（APNG 复位路径）；更稳妥的是在 `png_read_start_row`（pngrutil.c:4839 旁）加 `if (png_ptr->rowbytes >= (png_alloc_size_t)((uInt)-1)) png_error(...)`，让两条路径共用同一约束。
   - 回归：§10 的 T6。

3. **（中）警告抑制**：`pngpread.c:776` 的 `Extra compressed data in IDAT` 在 `PNG_FLAG_ZSTREAM_ENDED` 已置位后不再重复发出；或按「每 N 次」限流。

4. **（低）让渐进读取器的 IHDR 长度错误消息与顺序读取统一（`too short`/`too long` 而非 `Invalid IHDR length`），纯可观测性。

5. **（不建议改动）** 滤波分派与行长度算术本身：实测正确，改动收益低、风险高（`png.c:1961` 的注释明确说明「按实际使用尺寸检查更优但改动危险」）。若要在 32 位架构上再收紧，只应考虑把 `width+7 & ~7` 的上限从「8 字节/像素」降到「实际 `max_pixel_depth`」，收益也很小。

---

## 10. 回归清单

自动化脚本沿用本次工件（脚本与数据分目录，`python3 -I` 运行）：

- `pnggen.py`（485 个基础样本：447 合法 + 38 非法，附 `REFS.txt`）
- `pnggen_boundary.py`（306 个字节边界样本 + `REFS2.txt`）
- `pnggen_extra.py`（填充位、行错位、空 zlib 流、调色板填充位）
- `fuzz.py`（结构感知变异）
- `pngprobe.c` / `impprobe.c`（seq / prog / info / readpng 四种读法）

必测项：

| 编号 | 用例 | 期望（修复后） | 现状 |
| --- | --- | --- | --- |
| T1 | 截断 1/2/5 行（灰度 1/8bit、RGB8、RGBA16、交错、缺滤波字节、`cleanrows_k1..k3`） | `prog` 与 `seq` 一样报 `Not enough image data` | `prog` 全部 `RESULT ok`（14 个截断样本：12 个 `short_*`（cut1/2/5）+ `short_interlaced_cut2` + `short_missing_filter_byte`，以及 `cleanrows_k1..k3`）；只有 `short_empty_idat.png` 因别的原因报错 |
| T2 | `silent_partial_lastrow.png`（height=4，只有 2 行完整） | `prog` 报错（或至少交付行数必须等于 `height`） | `CALLBACKS 2/4`，行本身未受污染 |
| T3 | 合法图在 `prog` 下按 1/3/16 字节不规则喂入 | 与 `seq` 逐行完全一致（现基线：894 行集） | 通过 |
| T4 | 交错合法图 324 例（含 `padbits_il_bd1_pad0/pad1`） | `seq == prog` 逐行一致 | 通过 |
| T5 | `extra_rows.png` / `surplus_bomb_8MiB.png` | 仍为 warning（不是 error），且只告警一次 | 现告警 1 / 8148 次 |
| T6 | `wrap_4GiB_row.png`（rowbytes=2^32）、`wrap_avail6.png`（rowbytes=2^32+5）、`wrap_avail0.png`（rowbytes=0xFFFFFFFF），均需 `MAXLIMITS`+`NOGUARD` | `seq` 与 `prog` 都在 `png_read_start_row` 阶段拒绝 | `seq` 报 Not enough image data；`prog` 交付含未初始化字节的行并报 ok |
| T7 | 未知滤波字节 5/6/127/128/254/255（首行/末行/交错 pass1/调色板） | `bad adaptive filter value`，`ROWS_DONE` 精确 | 通过 |
| T8 | 未知滤波字节不越界索引 `read_filter[]`（ASan + 覆盖 `filter=4` 与 `filter=255`） | 无 ASan 报告 | 通过 |
| T9 | IHDR 全字段非法（38 个 `REF=ERROR` 样本） | `seq`/`prog` 全部 fatal，消息与 §2.2 表一致 | 通过 |
| T10 | 字节边界 306 例 × seq/prog | 612/612 与参考行一致 | 通过 |
| T11 | 大宽度 120 例（1000/8191/8192/8193/10000，含 65536 字节行） | seq/prog 一致 | 通过 |
| T12 | `png_read_png` / `png_image` 在 1e6×1e6 上的行为 | 前者 OOM 失败、后者 `image too large` | 通过 |
| T13 | 结构感知模糊 1300 次变异 / 1700 次探针运行（ASan+UBSan） | 0 crash | 0 crash |
| T14 | 上游 ctest（`/tmp/lp-test`） | 38/38 通过 | 38/38 通过 |
| T15 | `PNG_MAX_MALLOC_64K` 构建 | 65536 字节行报 `requires a row greater than 64KB` | 本构建未定义该宏，未测 |

T1/T2/T6 是修复前会失败（即暴露缺陷）的用例；其余是防止回归的护栏。

---

## 11. 结论适用的 PNG / 构建边界

本报告的结论只在下列边界内成立，超出即不适用：

1. **库版本**：libpng 1.8.0.git，`task/59` 快照（`git log` 仅 1 个提交 `7ef5852`）。与 `0026`/`0027`/`0047` 兄弟目录的 `pngrutil.c`/`pngread.c`/`png.c`/`pngrtran.c`/`pngset.c` 逐字节相同；`0026` 额外有 `PNG_FLAG_ROW_PAUSED`/`row_confirm_fn`（渐进行确认）实验性改动，本仓库**没有**这些字段。因此若日后移植该特性，§6.1 的结论需要重估（暂停机制会改变「何时可以判定流已结束」）。
2. **构建特性**：默认 `pnglibconf`：`PNG_READ_SUPPORTED`、`PNG_SEQUENTIAL_READ_SUPPORTED`、`PNG_PROGRESSIVE_READ_SUPPORTED`、`PNG_READ_INTERLACING_SUPPORTED`、`PNG_READ_TRANSFORMS_SUPPORTED`、`PNG_SET_USER_LIMITS_SUPPORTED`、`PNG_READ_APNG_SUPPORTED`、`PNG_MNG_FEATURES_SUPPORTED`、`PNG_TARGET_SPECIFIC_CODE_SUPPORTED`；本机未实际启用 SIMD（无 `__SSE2__` 等），因此 §4.1 的 SIMD 表项只在代码审查层面成立，未在 SSE2/NEON 构建上实测。
3. **架构**：实测全部在 x86-64 / Linux 6.8 / gcc 13.3 上完成。§5.1 的 32 位宽度上限（536870904）是公式计算，**未实测**（本机无 32 位运行时）。16 位/分段寻址（`PNG_SMALL_SIZE_T`、`PNG_MAX_MALLOC_64K`）完全未测。
4. **API 路径**：只覆盖 `png_read_info`+`png_read_row`/`png_read_image`（顺序）、`png_set_progressive_read_fn`+`png_process_data`（渐进）、`png_read_png`（全图）、`png_image_begin_read_from_memory`+`png_image_finish_read`（简化）。**未覆盖**：APNG 多帧（`png_read_frame_head`、`fcTL`/`fdAT`）、MNG intrapixel differencing（`png_permit_mng_features` + filter method 64，本调用序列必有 PNG 签名故不可达）、用户自定义 chunk、iCCP/zTXt 等压缩 ancillary chunk、写路径、`pngtest`/`pngvalid` 之外的测试程序。
5. **输入契约**：探针按 libpng 文档要求，在 `info_fn` 内（或顺序读取在 `png_read_info` 之后）调用 `png_set_interlace_handling` + `png_read_update_info`。若不满足该契约（`PROG_NOINIT=1` 实测：`CALLBACKS 0`，行全被丢弃、只有 7 条截断/多余数据警告），则 §4/§6 的一切结论都不成立——这是应用侧错误，且库**没有**检测它（`PNG_FLAG_DETECT_UNINITIALIZED` 只在启用读变换时置位，pngrtran.c:102-113；无变换时静默）。建议应用层始终调用 `png_read_update_info`。
6. **尺寸限制**：默认 `PNG_USER_WIDTH_MAX = PNG_USER_HEIGHT_MAX = 1000000`、`PNG_USER_CHUNK_MALLOC_MAX = 8000000`。§6.2 的 `uInt` 截断只在应用把宽度限制放宽到 ≥ 2^28（16bit RGBA）之后才可达；默认配置下 `rowbytes` 最大 8 MB，`avail_out` 截断**不可达**。§7 的 GiB 级放大同样需要放宽限制或使用全图 API。
7. **压缩器**：IDAT 流由本地 Python `zlib.compress` 生成。不同的 deflate 实现（`PNG_ZLIB_MAX_SIZE` 注释所提醒的「非 zlib 实现」）可能改变「多余数据」与「截断」的边界，§6.1 的具体样本未在其他压缩器下复现。
8. **错误处理**：探针使用 `setjmp/longjmp` 的默认 fatal 语义；`png_set_benign_errors(png_ptr, 1)` 会把部分 error 降级为 warning（例如 `Too much image data`、ADLER32 不匹配），这会改变 §7/§6.1 的「成功/失败」判定。所有结论均按默认（benign errors 关闭）给出。
9. **测试强度**：模糊测试 1300 次变异迭代、5 个变异策略，**不是**覆盖率引导的模糊测试；「未发现越界」应读作「该策略集合下未发现」，不能作为不存在越界的证明。若要更强的结论，建议接入 AFL++/libFuzzer 并以 `pngrutil.c`/`pngpread.c` 的滤波与行长度为覆盖目标。

---

## 附录 A：实测命令与关键输出

```bash
# 构建（普通 + sanitizer）
cmake -S . -B /tmp/lp-build -DCMAKE_BUILD_TYPE=Debug -DPNG_TESTS=OFF -DPNG_STATIC=ON -DPNG_SHARED=OFF
cmake -S . -B /tmp/lp-asan  -DCMAKE_BUILD_TYPE=Debug -DPNG_TESTS=OFF \
      -DCMAKE_C_FLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build /tmp/lp-asan -j8

# 探针
gcc -g -O1 -fsanitize=address,undefined -I/tmp/lp-asan -I. \
    /tmp/59-scripts/pngprobe.c /tmp/lp-asan/libpng18.a -lz -lm -o /tmp/59-scripts/pngprobe_asan

# 数据与批量核对（全部 -I 隔离模式）
python3 -I /tmp/59-scripts/pnggen.py          /tmp/59-data
python3 -I /tmp/59-scripts/pnggen_boundary.py /tmp/59-data/bnd
python3 -I /tmp/59-scripts/pnggen_extra.py    /tmp/59-data
python3 -I /tmp/59-scripts/run_sweep.py /tmp/59-data /tmp/59-scripts/pngprobe_asan both
python3 -I /tmp/59-scripts/fuzz.py /tmp/59-data /tmp/59-scripts/pngprobe_asan 400 both
FUZZSEED=1 python3 -I /tmp/59-scripts/fuzz.py /tmp/59-data /tmp/59-scripts/pngprobe_asan 300 seq
# (FUZZSEED 2、3 同理；四次合计 1300 次变异 / 1700 次探针运行)
```

关键输出（原样）：

```
# 截断 — seq 拒绝，prog 放行
short_ct2_bd8_cut1.png  seq: RESULT error / ERR Not enough image data / ROWS_DONE 3
                        prog: RESULT ok / WARN 0 / CALLBACKS 3 (height=4)

# 未知滤波字节
badfilter_5.png         seq: ERR bad adaptive filter value / ROWS_DONE 0
                        prog: ERR bad adaptive filter value
badfilter_final_row4png seq: ERR bad adaptive filter value / ROWS_DONE 3

# 4 GiB 行边界（放宽限制，MALLOC_PERTURB_=171 -> malloc 填充字节为 0x54）
# HEAD 采样的是回调收到的 row（即 row_buf+1，载荷起点），滤波字节本身不在其中
wrap_4GiB_row.png       seq:  RESULT error / ERR Not enough image data / ROWS_DONE 0
  (rowbytes=2^32, avail_out=(2^32+1) mod 2^32 = 1)
                        prog: RESULT ok / CALLBACKS 2 / ENDED 1
                              HEAD 5454...5454   (载荷全为填充值，库从未写入)

wrap_avail6.png         prog: RESULT ok / CALLBACKS 2 / ENDED 1
  (rowbytes=2^32+5, avail_out=6)
                              HEAD 11111111115454540000000000545454
                              (前 6 字节来自 IDAT，其余为填充值)

wrap_avail6_h64.png     prog: RESULT ok / CALLBACKS 9 / ENDED 1 / INFO height=64
  (rowbytes=2^32+5, height=64, 压缩文件 71 字节)
                              CB1 first8=1111111111aaaaaa  (MALLOC_PERTURB_=0x55)
                              CB2..CB9 first8=0000000000aaaaaa
                              -> 9 行被回调，仅 9*6 字节来自 IDAT

wrap_avail0.png         prog: RESULT error / ERR Decompression error in IDAT
  (rowbytes=0xFFFFFFFF, avail_out=0)

# 边界与正确性
boundary cases: 306 ; seq+prog ok 612, bad 0
checked 120 bad 0 nonok 0        (大宽度)
ctest: 100% tests passed, 0 tests failed out of 38
```

