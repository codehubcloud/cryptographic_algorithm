# 代码风格规范(CODE_STYLE)

## 1. 目的与适用范围

1. 本规范适用于 `core/`,`cmake/`,`build.py` 等项目自维护代码.
2. `drivers/`,`free_rtos/` 属于第三方代码, 原则上不按本规范做风格改写, 只做必要最小修改.

## 2. 命名规范

### 2.1 类型命名

1. 结构体: `大驼峰 + _S`, 例如 `GpioInit_S`.结构体的定义使用 `typedef` 的形式, 结构体名使用大驼峰 `_S` 的形式, 如 `BaseName_S`, 结构体成员变量使用小驼峰, 如 `baseName`.

```c
typedef struct
{
    int baseName;
    int driction;
    int index;
    int versionName;
}BaseName_S;
```

2. 枚举: `大驼峰 + _E`, 例如 `OsPriority_E`.枚举类型使用 `typedef` 的形式, 枚举名使用大驼峰 `_E` 的形式, 如 `BaseName_E`, 枚举变量使用全大写下划线形式, 如 `NUM_BASE = 0`.

```c
typedef enum
{
    NUM_BASE = 0,
    NUM_MAX,
    NUM_MIN,
}BaseName_E;
```

3. 联合体: `大驼峰 + _U`, 例如 `SomeValue_U`.联合体类型使用 `typedef` 的形式, 联合体名使用大驼峰 `_U` 的形式, 如 `BaseName_U`, 联合体成员变量使用小驼峰, 如 `baseName`.

```c
typedef union
{
    int baseName;
    int versionName;
    int index;
}BaseName_U;
```

4. 函数指针类型: `大驼峰 + FuncPtr`, 例如 `OsThreadFuncPtr`.

### 2.2 变量命名

1. 全局变量: `g_ + 小驼峰`, 例如 `g_handle`.
2. 文件内静态变量: 同样使用小驼峰, 必要时可加语义前缀.
3. 布尔语义变量建议使用 `is/has/need` 前缀.
4. 禁止滥用单字符变量，需要能表明含义;循环计数器可使用 `i/j/k`.

### 2.3 函数命名

1. 函数名使用大驼峰, 示例: `SystemClockConfig`,`ErrorHandler`.
2. 静态内部函数同样使用大驼峰, 示例: `MxGpioInit`,`LedBlinkTask`.
3. 参数名与局部变量使用小驼峰.

### 2.4 宏与常量

1. 宏名全大写下划线: `CONFIG_TICK_RATE_HZ`.
2. 宏值使用括号包裹: `#define LED0_PIN (GPIO_PIN_5)`.
3. 与单位有关的变量名应体现单位后缀: `g_ledBlinkIntervalMs`.

## 3. 格式与排版

1. 行宽建议不超过 160 字符.
2. `if/for/while/switch` 即使只有一条语句, 也必须使用 `{}`.
3. 一行只声明一个变量, 不写 `int a, b, c;`, 要写成 `int a; int b; int c;`.
4. 运算符与逗号两侧保留必要空格, 保持可读性.
5. 文件使用 UTF-8 编码, 避免混入不可见特殊字符(如 BOM).

## 4. 注释规范

### 4.1 文件头注释

每个自维护源文件应有文件头, 包含至少以下信息: 

1. File Name
2. Function
3. Author
4. Version
5. Date
模板：
```c
/*******************************************************************************
 * File Name : xxx.c
 * Function  : 文件功能说明
 * Author    : xxx
 * Version   : V1.0
 * Date      : YYYY/MM/DD
 ******************************************************************************/
```

### 4.2 函数注释

每个非平凡函数应提供统一注释块, 每个函数的不管是声明还是定义都需要又注释, 注释格式： * @param[in] :

@param[out]: 写一次就行,不能写多次, 参数写在一行, 中间用, 分割 如 * @param[in] : a --xxxx, b --yyyy * @param[out]: a --xxxx, b --yyyy
@brief, @param[in], @param[out], @return, @note 这些无论函数有没有对应的内容都要写出来, 如果没有内容写无
模板: 

```c
/*******************************************************************************
 * @brief      : 功能简介
 * @param[in]  : 输入参数说明
 * @param[out] : 输出参数说明
 * @return     : 返回值说明
 * @note       : 注意事项/上下文约束
 ******************************************************************************/
```

要求: 

1. 注释描述"为什么"和"约束", 不要重复函数名本身.
2. ISR,并发,时序相关函数必须写清调用上下文限制.

### 4.3 代码内注释
1. 代码内注释全部采用中文注释, 以便团队成员理解.

### 4.4 不要这种注释
```c
/** @addtogroup CMSIS
 * @{
 */

/** @addtogroup stm32l052xx
 * @{
 */


/**
 * @}
 */
```
### 4.5这种注释需要修改
```c
/** @addtogroup Peripheral_interrupt_number_definition
 * @{
 */

/**
 * @brief stm32l052xx Interrupt Number Definition, according to the selected device
 *        in @ref Library_configuration_section
 */
```
改为
```c
/*
 * 中断号定义, 根据具体设备型号而定
 */

/*
 * 根据库配置部分中选择的设备，定义 stm32l052xx 中断号
 */
```


## 5. 设计与实现约束

1. 初始化失败统一走 `ErrorHandler()` 或明确错误分支, 不静默吞错.
2. 中断上下文禁止调用阻塞 API.
3. 与 RTOS 相关代码应显式区分任务上下文与 ISR 上下文.
4. 新增任务需明确: 任务优先级,栈大小,阻塞策略.
5. 新增硬件配置必须同步更新文档(`docs/BUILD_GUIDE.md` 与 `docs/DESIGN_DOCUMENT.md`).

## 6. 示例

### 6.1 推荐

```c
static const uint32_t g_ledBlinkIntervalMs = 200U;

static void LedBlinkTask(void* argument)
{
    (void)argument;

    for (;;) {
        HAL_GpioWritePin(LED0_GPIO_PORT, LED0_PIN, GPIO_PIN_RESET);
        HAL_GpioWritePin(LED1_GPIO_PORT, LED1_PIN, GPIO_PIN_SET);
        OS_Delay(g_ledBlinkIntervalMs);
    }
}
```

### 6.2 不推荐

```c
int a,b; // 同行多变量 + 无语义命名
if (x) y++; // 单行if无大括号
```

## 7. 提交前自检清单

1. 是否遵守命名规则(类型后缀,全局变量前缀).
2. 是否所有关键函数都补齐了统一注释块.
3. 是否新增代码存在明确错误处理路径.
4. 是否引入了 ISR 与任务上下文混用风险.
5. 是否同步更新文档与配置.
