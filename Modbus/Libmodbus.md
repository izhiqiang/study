# libmodbus

版本号：V3.0.6(已加入3.1.4版本补充)

# 特点

​     libmodbus是一个快速、跨平台的Modbus库。

# 概要

#include <modbus.h>

cc `pkg-config --cflags --libs libmodbus` files

# 描述

libmodbus是一个与使用Modbus协议的设备进行数据发送/接收的库。该库包含各种后端(backends)通过不同网络进行通信(例如，RTU模式下的串口或TCP / IPv6中的以太网)。

 http://www.modbus.org网站提供了协议规范文档http://www.modbus.org/specs.php。

libmodbus提供了较低通信层的抽象，并在所有支持的平台上提供相同的API。

本文档介绍了了libmodbus概念，介绍了libmodbus如何从在不同的硬件和平台中实现Modbus通信，并为libmodbus库提供的函数提供了参考手册。

# 环境(contexts)

Modbus协议包含许多变体(例如串行RTU或Ehternet TCP)，为了简化变体的实现，该库被设计成为每个变体使用后端(backends)。后端也是满足其他要求(例如实时操作)的便捷方法。每个后端都提供了一个特定的函数来创建一个新的modbus_t环境。 modbus_t环境是一个不透明的结构，包含根据所选变体与其他Modbus设备建立连接的所有必要信息。

# RTU环境

RTU后端(远程终端单元)用于串口通信，并使用用于协议通信的数据的紧凑的二进制表示形式。RTU格式遵循命令/数据，和CRC(cyclic redundancy check循环冗余校验)作为错误检查机制，以确保数据的可靠性。Modbus RTU是可用于Modbus的最常用的实现方式。Modbus RTU消息必须连续发送，不能有字符间隔(摘自Wikipedia，Modbus， http://en.wikipedia.org/wiki/Modbus  截至2011年3月13日，格林尼治时间20:51)。

Modbus RTU框架调用一个从站，一个处理Modbus请求的设备/服务器，以及一个发送请求的客户端(主站)。通信始终由主站服务端发起。

许多Modbus设备可以在同一个的物理链路上连接在一起(总线结构)，因此在发送消息之前，必须使用modbus_set_slave设置从站(接收设备 )ID。如果您正在运行一个从站，则其从站号将用于过滤接收的消息。

 

## 创建modbus RTU 环境

### 初试化RTU环境指针 

modbus_t *modbus_new_rtu(const char *device, int baud, char parity, int data_bit, int stop_bit)

```c++
modbus_t *modbus_new_rtu(const char *device, int baud, char parity, int data_bit, int stop_bit);

//参考代码：
modbus_t *ctx;

ctx = modbus_new_rtu("/dev/ttyUSB0", 115200, 'N', 8, 1);
if(ctx == NULL) {
    fprintf(stderr, "Unable to create the libmodbus context\n");
    return -1;
}
```

这个 modbus_new_rtu()函数会生成并初始化一个modbus的结构体来在串行线路中使用RTU模式进行通讯。

device 指定OS处理的串行端口的名称，比如 /dev/ttyS0 or /dev/ttyUSB0，在windows系统上，如果COM编号大于9，必须要在COM前加上\\.\ ，比如 \\\\.\\COM10.，参照http://msdn.microsoft.com/en-us/library/aa365247(v=vs.85).aspx

 **baud** ：指定连接的波特率，比如9600, 19200, 57600, 115200等。

**parity** ：代表奇偶检验位，有如下值：

**N**   无奇偶校验

**E**  偶数校验

**O**  奇数校验

**data_bit** ：指定数据的位数，允许值有： 5, 6, 7 ,8.

**stop_bit** ：指定停止位位数，允许值有1和2.

返回：如果建立成功，modbus_new_rtu()函数将返回指向modbus_t结构的指针。 否则它将返回NULL并将errno设置为An invalid argument was given.。

## 设置串口模式

### 获取当前串口模式 

int modbus_rtu_get_serial_mode(modbus_t *ctx);

```c++
int modbus_rtu_get_serial_mode(modbus_t *ctx);
```

返回：如果成功, 函数应返回 **MODBUS_RTU_RS232** 或 **MODBUS_RTU_RS485** 。

否则, 它将返回-1并将 `errno` 设为**The current libmodbus backend is not RTU**.

只用于RTU环境。

### 设置串口模式 

int modbus_rtu_set_serial_mode(modbus_t *ctx, int mode);

```c++
int modbus_rtu_set_serial_mode(modbus_t *ctx, int mode);
```

**mode**: 填入 `MODBUS_RTU_RS232` 或 `MODBUS_RTU_RS485` 

返回值：如果成功, 函数应返回0。否则, 它将返回-1 并将 `errno` 设置为下面定义的值之一。

**EINVAL** The current libmodbus backend is not RTU.

**ENOTSUP** The function is not supported on your platform.。

如果对 ioctl() 的调用失败, 将返回 ioctl 的错误代码。

### 在 RTU环境下 中获取当前RTS模式 

int modbus_rtu_get_rts(modbus_t *ctx)(3.1.4版本补充)

```c++
int modbus_rtu_get_rts(modbus_t *ctx);
```

可以获得在当前ctx环境下发送请求的的模式。

返回值：

   `MODBUS_RTU_RTS_NONE` 

   `MODBUS_RTU_RTS_UP ` 

   `MODBUS_RTU_RTS_DOWN ` 

   `-1`，即调用失败，并设置 `EINVAL` 为 The libmodbus backend is not RTU.

 

### 在RTU环境下获取设置RTS模式 

int modbus_rtu_set_rts(modbus_t *ctx, int mode)(3.1.4版本补充)

```c++
int modbus_rtu_set_rts(modbus_t *ctx, int mode);

//例子：启动有正极性的RTS模式
modbus_t *ctx;
uint16_t tab_reg[10];

ctx = modbus_new_rtu("/dev/ttyS0", 115200, 'N', 8, 1);
modbus_set_slave(ctx, 1);
modbus_rtu_set_serial_mode(ctx, MODBUS_RTU_RS485);
modbus_rtu_set_rts(ctx, MODBUS_RTU_RTS_UP);

if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connexion failed: %s\n", modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}

rc = modbus_read_registers(ctx, 0, 7, tab_reg);
if(rc == -1) {
    fprintf(stderr, "%s\n", modbus_strerror(errno));
    return -1;
}

modbus_close(ctx);
modbus_free(ctx);
```

设置发送请求模式用于在RS485串行总线上进行通讯，默认模式为MODBUS_RTU_RTS_NONE，在把数据写入线路之前不会有信号发出。

要启用RTS 模式, 必须使用 MODBUS_RTU_RTS_UP或MODBUS_RTU_RTS_DOWN, 这些模式启用 RTS 模式并同时设置极性。使用MODBUS_RTU_RTS_UP时, 将RTS 标志位置为使能并进行 ioctl 调用, 然后在1毫秒的延迟后在总线上写入数据, 然后将 RTS 标志位置为非使能进行另一个 ioctl 调用, 并再次延迟1毫秒。MODBUS_RTU_RTS_DOWN模式与之类似, 但使用相反的 RTS 标志位。

如果成功, 函数应返回0。否则, 它将返回-1 并将 errno 设置为The libmodbus backend isn’t RTU or the mode given in argument is invalid.。

 

### 自定义RTS实现 

int modbus_rtu_set_custom_rts(modbus_t *ctx, void(set_rts)(modbus_t ctx, int on))(3.1.4版本补充)

```c++
int modbus_rtu_set_custom_rts(modbus_t *ctx, void(set_rts)(modbus_t ctx, int on));
```

设置传输前后设置RST PIN要调用的自定义函数，默认情况下，默认情况下，设置为使用IOCTL调用切换RTS PIN的内部函数。

注意，该函数遵循RTS模式，必须使用值MODBUS_RTU_RTS_UP或MODBUS_RTU_RTS_DOWN来调用该函数。

返回：如果成功, `modbus_rtu_set_custom_rts()` 函数应返回0。否则, 它将返回 `-1` 并将 `errno` 设置为The libmodbus backend is not RTU.

 

### 获取RTU中当前RTS延迟 

int modbus_rtu_get_rts_delay(modbus_t *ctx);(3.1.4版本补充)

```c++
int modbus_rtu_get_rts_delay(modbus_t *ctx);
```

返回：成功则以微秒为单位返回当前RTS延迟。否则它将返回-1并设置errno为The libmodbus backend is not RTU.。

 

### 设置RTU中的RTS延迟  

 int modbus_rtu_set_rts_delay(modbus_t *ctx, int us);(3.1.4版本补充)

```c++
int modbus_rtu_set_rts_delay(modbus_t *ctx, int us);
```

设置请求发送延迟。

返回：成功，返回0。否则它将返回-1并设置errno：The libmodbus backend is not RTU or a negative delay was specified.

# TCP(IPv4)环境

TCP后端实现了用于通过TCP / IPv4网络进行通信的Modbus变体。它不需要校验和计算，因为底层TCP会处理相同的功能。

## 创建Modbus TCP环境 

modbus_t *modbus_new_tcp(const char *ip, int port);

```c++
modbus_t *modbus_new_tcp(const char *ip, int port)；
//例子:
modbus_t *ctx;

ctx = modbus_new_tcp("127.0.0.1", 1502);
if(ctx == NULL) {
    fprintf(stderr, "Unable to allocate libmodbus context\n");
    return -1;
}

if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}
```

**ip**:希望连接的服务器ip地址

**port**：要使用的 TCP 端口。将端口设置为MODBUS_TCP_DEFAULT_PORT使用默认值之一(502)。使用大于或等于1024的端口号很方便, 因为没有必要拥有管理员权限。

返回：成功返回指向`modbus_t`结构体的指针。否则, 它应返回 `NULL `并将 `errno` 设置为An invalid IP address was given.

# TCP PI(IPv4和IPv6)环境

TCP PI(Protocol Indepedent)后端实现用于通过TCP IPv4和IPv6网络进行通信的Modbus变体。 它不需要校验和计算，因为较低层负责相同的操作。 与单独的TCP IPv4后端不同，TCP PI后端提供主机名解析，但它消耗大约1Kb的额外内存。

### 创建Modbus TCP PI环境

modbus_t *modbus_new_tcp_pi(const char *node, const char *service);

```c++
modbus_t *modbus_new_tcp_pi(const char *node, const char *service);
//例子
modbus_t *ctx;

ctx = modbus_new_tcp_pi("::1", "1502");
if(ctx == NULL) {
    fprintf(stderr, "Unable to allocate libmodbus context\n");
    return -1;
}

if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}
```

应分配和初始化一个 `modbus_t` 结构, 以便与一个 IPv4 或 Ipv6 服务器进行通信。

**node **参数指定要连接的主机的主机名或 IP 地址, 例如。192.168.0.5 ，:: 1或server.com.

**service **参数是要连接到的服务名称/端口号。要使用默认的接口端口, 请使用字符串 "502"。在许多 Unix 系统上, 使用大于或等于1024的端口号是很方便的, 因为没有必要拥有管理员权限。

返回值：成功返回指向**modbus_t**结构的指针。否则, 它应返回 NULL 并将 errno 设置为The node string is empty or has been truncated. The service string is empty or has been truncated。

 

# 通用函数：

在使用任何libmodbus函数之前，调用者必须使用上述功能分配和初始化 modbus_t环境，然后提供以下函数来修改和释放环境：

## 释放modbus环境

void modbus_free(modbus_t *ctx);

```c++
void modbus_free(modbus_t *ctx);
```

## 设置从站ID 

int modbus_set_slave(modbus_t *ctx, int slave);(3.1.4版本补充)

```c++
int modbus_set_slave(modbus_t *ctx, int slave);
//例子
modbus_t *ctx;

ctx = modbus_new_rtu("/dev/ttyUSB0", 115200, 'N', 8, 1);
if(ctx == NULL) {
    fprintf(stderr, "Unable to create the libmodbus context\n");
    return -1;
}

rc = modbus_set_slave(ctx, YOUR_DEVICE_ID);
if(rc == -1) {
    fprintf(stderr, "Invalid slave ID\n");
    modbus_free(ctx);
    return -1;
}

if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}
```

设定libmodbus环境中的slave ID。

若为RTU模式

定义远程设备的从站ID以在主站模式下进行通信，或将内部从站ID设置为从站模式。 根据协议，Modbus设备只接受包含了其从机号码(slave number)或特殊广播号码的消息。

若为TCP模式

如果消息必须到达串行网络上的设备，则仅在TCP中需要从站号码。 某些不兼容的设备或软件(例如modpoll)使用从站ID作为单元标识符，这是不正确的(参见Modbus Messaging Implementation Guide v1.0b的第23页)没有从站值，故障的远程设备或软件会丢弃请求！ 特殊值MODBUS_TCP_SLAVE(0xFF)可用于TCP模式以恢复默认值。

广播地址是 MODBUS_BROADCAST_ADDRESS 。 当您希望网络中的所有Modbus设备都收到请求时，必须使用此特殊值。

返回：成功则返回0，否者返回 `-1` 并将 `errno` 设定为 **The slave number is invalid.**。

 

## 启用调试模式 

int modbus_set_debug(modbus_t *ctx, int flag);(3.1.4版本补充)

```c++
int modbus_set_debug(modbus_t *ctx, int flag);
```

通过是用flag设置debug调试标志位，默认情况下，布尔标志位flag被设置为FALSE，当falg被设置为TRUE时，会在stdout和stderr上显示很多冗长的信息，可以用于显示modbus消息的字节：

[00][14][00][00][00][06][12][03][00][6B][00][03] 
Waiting for a confirmation…
<00><14><00><00><00><09><12><03><06><02><2B><00><00><00><00>
返回：成功返回0，否则返回-1.

 

## 超时设置： 

### 获取字节之间的超时 

int modbus_get_byte_timeout(modbus_t *ctx, uint32_t *to_sec, uint32_t *to_usec);

```c++
int modbus_get_byte_timeout(modbus_t *ctx, uint32_t *to_sec, uint32_t *to_usec);
//例子：
uint32_t to_sec;
uint32_t to_usec;

/* Save original timeout */
modbus_get_byte_timeout(ctx, &to_sec, &to_usec);
```

实现在`to_sec`和`to_usec`参数中存储同一消息的两个连续字节之间的超时间隔。

返回：成功返回0，否则返回-1

 

### 设置字节之间超时间隔 

void modbus_set_byte_timeout(modbus_t *ctx, uint32_t to_sec, uint32_t to_usec);

```c++
void modbus_set_byte_timeout(modbus_t *ctx, uint32_t to_sec, uint32_t to_usec);
```

设置同一消息的两个连续字节之间的超时间隔。超时是在select()函数返回之前所经过的时间量的上限, 如果时间超过定义的超时, 则等待响应的函数将引发ETIMEDOUT错误。to_usec参数的值必须在范围0到999999之间。

如果to_sec和to_usec都为零, 则不会使用此超时。在这种情况下, modbus_set_response_timeout()控制响应的整个处理, 必须在响应超时过期之前接收完整的确认响应。只设置字节超时为1时, 响应超时仅用于等待响应的第一个字节。

返回：成功0，失败返回-1并设置errno为：The argument ctx is NULL or to_usec is larger than 1000000.

 

### 获取响应超时时间

void modbus_get_response_timeout(modbus_t *ctx, struct timeval *timeout);

```c++
void modbus_get_response_timeout(modbus_t *ctx, struct timeval *timeout);
//例子
struct timeval old_response_timeout;
struct timeval response_timeout;

/* Save original timeout保存原始的超时参数 */
modbus_get_response_timeout(ctx, &old_response_timeout);

/* Define a new and too short timeout!定义一个新的更短的超时参数 */
response_timeout.tv_sec = 0;
response_timeout.tv_usec = 0;
modbus_set_response_timeout(ctx, &response_timeout);
```

modbus_get_response_timeout 函数会保存用于等待超时参数中的响应的超时间隔。

 

### 设置超时响应时间 

void modbus_set_response_timeout(modbus_t *ctx, struct timeval *timeout);

```c++
void modbus_set_response_timeout(modbus_t *ctx, struct timeval *timeout);
//例子
struct timeval old_response_timeout;
struct timeval response_timeout;

/* Save original timeout */
modbus_get_response_timeout(ctx, &old_response_timeout);

/* Define a new and too short timeout! */
response_timeout.tv_sec = 0;
response_timeout.tv_usec = 0;
modbus_set_response_timeout(ctx, &response_timeout);
```

modbus_set_response_timeout 函数应设置用于等待响应的超时间隔。如果在接收响应之前等待的时间超过给定的超时时间，则会引发错误。

 

### 设置错误恢复模式 

int modbus_set_error_recovery(modbus_t *ctx, modbus_error_recovery_mode error_recovery);(3.1.4版本补充)

```c++
int modbus_set_error_recovery(modbus_t *ctx, modbus_error_recovery_mode error_recovery);
//例子
modbus_set_error_recovery(ctx, MODBUS_ERROR_RECOVERY_LINK |
                          MODBUS_ERROR_RECOVERY_PROTOCOL);
```

用于设置连接失败或者不期望接收到的字节时应用的错误恢复模式，参数  error_recovery 可以是按位(bitewise)或者其他检误方式(ed)使用0或者以下的常量。

默认情况下没有错误恢复(`MODBUS_ERROR_RECOVERY_NONE`), 因此应用程序负责控制 libmodbus 函数返回的错误值, 并在必要时处理它们。

设置(`MODBUS_ERROR_RECOVERY_LINK`)时, 库将尝试在 libmodbus 上下文的响应超时定义的延迟之后重新连接。此模式将尝试无限关闭/连接的循环, 直到成功发送呼叫, 并只尝试一次重新建立连接上的选择/读呼叫(如果连接已关闭, 读取的值肯定是不可用的, 在重联后, 除了为从机/主机)。此模式还将在某些情况下基于当前响应超时(例如, 选择调用超时) 后的延迟运行刷新请求。如果网络到远程目标单元已关闭, 重新连接尝试可能会挂起几秒钟。

设置(`MODBUS_ERROR_RECOVERY_PROTOCOL`)时, 将使用睡眠和冲洗序列来清理正在进行的通信, 这可能发生在消息长度无效时, TID错误或接收的函数代码不是预期的。响应超时延迟将用于睡眠。

模式是掩码值, 因此它们是互补的。

建议不要为从机/主机启用错误恢复。

返回值：成功返回0，否则返回-1并吧errno设为：The value of the argument error_recovery is not positive.

 

### 设置环境套接字(socket )

int modbus_set_socket(modbus_t *ctx, int s);

```c++
int modbus_set_socket(modbus_t *ctx, int s);
//例子
ctx = modbus_new_tcp("127.0.0.1", 1502);
server_socket = modbus_tcp_listen(ctx, NB_CONNECTION);

FD_ZERO(&rdset);
FD_SET(server_socket, &rdset);

/* .... */

if(FD_ISSET(master_socket, &rdset)) {
    modbus_set_socket(ctx, master_socket);
    rc = modbus_receive(ctx, query);
    if(rc != -1) {
        modbus_reply(ctx, query, rc, mb_mapping);
    }
}
```

在libmobus中设置环境套接字火文件描述符，对于管理到同一个主机的多个从机连接非常有效。

返回：成功返回0，否则返回-1并设置errno。

 

### 获取环境套接字(socket) 

int modbus_get_socket(modbus_t *ctx);

```c++
int modbus_get_socket(modbus_t *ctx);
```

返回：成功则返回当前环境的套接字(socket)或文件描述符，否则返回-1并设置errno。

 

### 检索当前标头长度 

int modbus_get_header_length(modbus_t *ctx);

```c++
int modbus_get_header_length(modbus_t *ctx);
```

从后端检索当前报头长度。此函数便于操作消息, 因此它仅限于低级操作。

返回：整形标头长度值。

libmodbus的环境是线程安全的，可以在必要时共享尽可能多的应用程序线程, 而调用方不需要任何额外的锁定。

### 用于数据操作的宏

`MODBUS_GET_HIGH_BYTE(data)` 获取高位字节

`MODBUS_GET_LOW_BYTE(data)` 获取低位字节

`MODBUS_GET_INT32_FROM_INT16(tab_int16, index)` 从两个int16数据建立一个int32数据,从tab_int16[index]开始。

`MODBUS_GET_INT16_FROM_INT8(tab_int8, index)`从两个int8数据建立一个int16数据，从tab_int8[index]开始。

`MODBUS_SET_INT16_TO_INT8(tab_int8, index, value)`将一个int16数据设置为从tab_int8[index]开始的两个int8数据。

`MODBUS_SET_INT32_TO_INT16(tab_int16, index, value)`将一个int32数据设置为从tab_int16[index]开始的两个int16数据。

`MODBUS_SET_INT64_TO_INT16(tab_int16, index, value)`将一个int64数据设置为从tab_int16[index]开始的四个int16数据。

 

## 用于操作位和字节的函数(3.1.4版本修改)

### 从单个字节值设置多个位

void modbus_set_bits_from_byte(uint8_t *dest, int index, const uint8_t value);

```c++
void modbus_set_bits_from_byte(uint8_t *dest, int index, const uint8_t value);
```

从单个字设置多个位，value字节中所有8位都会被写到dest数组中从index索引开始的位置。

 

### 从字节数组设置多个位

void modbus_set_bits_from_bytes(uint8_t *dest, int index, unsigned int nb_bits, const uint8_t *tab_byte);

```c++
void modbus_set_bits_from_bytes(uint8_t *dest, int index, unsigned int nb_bits, const uint8_t *tab_byte);
```

通过读取字节数组来设置位，从tab_byte数组第一个开始的所有字节都会被写到dest数组中从index索引开始的位置。

### 从多个位获取数值

uint8_t modbus_get_byte_from_bits(const uint8_t *src, int index, unsigned int nb_bits);

```c++
uint8_t modbus_get_byte_from_bits(const uint8_t *src, int index, unsigned int nb_bits);
```

从多个位提取一个值，从src的index位置开始的的nb_bits位都会被读取为一个单独的值，为了获取一个完整的字节，把nb_bits设置为8。

返回：返回一个读取后的字节。

 

## 设置或获取浮点数

### ABCD顺序获取浮点值

float modbus_get_float_abcd(const uint16_t *src);

```c++
float modbus_get_float_abcd(const uint16_t *src);
```

从4个字节获取浮点值。src数组必须是两个16位数值的指针。例如第一个值为0x0020,第二个值为0xF147,则浮点值被读为123456.0。

返回：浮点值。

### ABCD顺序存储浮点值

void modbus_set_float_abcd(float f, uint16_t *dest);

```c++
void modbus_set_float_abcd(float f, uint16_t *dest);
```

将f浮点数存储到dest数组所指的两个16位值得指针。

 

### BADC顺序获取浮点值

float modbus_get_float_badc(const uint16_t *src);

```c++
float modbus_get_float_badc(const uint16_t *src);
```

从4个字节获取浮点值。src数组必须是两个16位数值的指针。例如第一个值为0x2000,第二个值为0x47F1,则浮点值被读为123456.0。

返回：浮点值。

### BADC顺序存储浮点值

void modbus_set_float_badc(float f, uint16_t *dest);

```c++
void modbus_set_float_badc(float f, uint16_t *dest);
```

将f浮点数存储到dest数组所指的两个16位值得指针。

### CDAB顺序获取浮点值

float modbus_get_float_cdab(const uint16_t *src);

```c++
float modbus_get_float_cdab(const uint16_t *src);
```

从4个字节获取浮点值。src数组必须是两个16位数值的指针。例如第一个值为0x0020,第二个值为0xF147,则浮点值被读为123456.0。

返回：浮点值。

### CDAB顺序存储浮点值

void modbus_set_float_cdab(float f, uint16_t *dest);

```c++
void modbus_set_float_cdab(float f, uint16_t *dest);
```

将f浮点数存储到dest数组所指的两个16位值得指针

### DCBA顺序获取浮点值

float modbus_get_float_dcba(const uint16_t *src);

```c++
float modbus_get_float_dcba(const uint16_t *src);
```

从4个字节获取浮点值。src数组必须是两个16位数值的指针。例如第一个值为0x47F1,第二个值为0x2000,则浮点值被读为123456.0。

返回：浮点值。

### DCBA顺序存储浮点值

void modbus_set_float_dcba(float f, uint16_t *dest);

```c++
void modbus_set_float_dcba(float f, uint16_t *dest);
```

将f浮点数存储到dest数组所指的两个16位值得指针

# 连接

## 建立连接 

int modbus_connect(modbus_t *ctx);

```c++
int modbus_connect(modbus_t *ctx);
//例子
modbus_t *ctx;

ctx = modbus_new_tcp("127.0.0.1", 502);
if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}
```

使用参数给定的环境信息，建立与主机、网络或总线的连接。

返回：成功返回0，错误返回-1并将errno设置为底层平台的系统呼叫。

## 关闭连接 

void modbus_close(modbus_t *ctx);

```c++
void modbus_close(modbus_t *ctx);
//例子
modbus_t *ctx;

ctx = modbus_new_tcp("127.0.0.1", 502);
if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}

modbus_close(ctx);
modbus_free(ctx);
```

关闭与下级建立的连接。

返回值：无

## 冲洗未连接数据

int modbus_flush(modbus_t *ctx);

```c++
int modbus_flush(modbus_t *ctx);
```

用于丢弃已接收到的单未读取到与ctx环境相匹配的套接字(socket)或文件描述符。

返回：成功返回0或刷新字节数，否则返回-1并设置errno。

# 主机(客户端Client)

## 读取数据

### 读取位(读取线圈状态) 

int modbus_read_bits(modbus_t *ctx, int addr, int nb, uint8_t *dest);

```c++
int modbus_read_bits(modbus_t *ctx, int addr, int nb, uint8_t *dest);
```

用于读远程设备的 addr 地址开始的共nb 位(线圈)的状态，读取的结果以无符号的字节(8 位) 设置为TRUE或FALSE存储在目的数组dest中。

您必须注意分配足够的内存以将结果存储在dest位置，至少是nb* sizeof(uint8_t) 的内存大小。

 该函数使用0x01功能码(读取线圈状态)。

返回：成功返回读取位的数目即nb，失败返回-1并设置errno为Too many bits requested。

译者注：即取得一组逻辑线圈的当前状态(1/0)。

### 读取输入位(读取输入状态) 

int modbus_read_input_bits(modbus_t *ctx, int addr, int nb, uint8_t *dest);

```c++
int modbus_read_input_bits(modbus_t *ctx, int addr, int nb, uint8_t *dest);
```

用于读远程设备的 addr 地址开始的共nb 位(输入)的状态。读取的结果以无符号的字节(8 位) 设置为TRUE或FALSE存储在目的数组dest中。

您必须注意分配足够的内存以将结果存储在dest位置，至少是nb* sizeof(uint8_t) 的内存大小。

该函数使用0x02 功能码(读取输入状态)。

返回：成功返回读取输入位的数目即nb，失败返回-1并设置errno为Too many discrete inputs requested。

译者注：即取得一组开关输入的当前状态(1/0)。

### 读取保持寄存器 

int modbus_read_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);

```c++
int modbus_read_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);
//例子
modbus_t *ctx;
uint16_t tab_reg[64];
int rc;
int i;

ctx = modbus_new_tcp("127.0.0.1", 1502);
if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}

rc = modbus_read_registers(ctx, 0, 10, tab_reg);
if(rc == -1) {
    fprintf(stderr, "%s\n", modbus_strerror(errno));
    return -1;
}

for(i=0; i < rc; i++) {
    printf("reg[%d]=%d(0x%X)\n", i, tab_reg[i], tab_reg[i]);
}

modbus_close(ctx);
modbus_free(ctx);
```

 用于读远程设备的 addr 地址开始的共nb 位(保持寄存器)的状态。读取结果以uint(16 位) 的形式存储在dest数组中。

您必须注意分配足够的内存以将结果存储在dest位置，至少是nb* sizeof(uint16_t) 的内存大小。

该函数使用0x03 功能码(读取保持寄存器)。

返回：成功返回读取输入位的数目即nb，失败返回-1并设置errno为Too many registers requested。

 

### 读取输入寄存器

int modbus_read_input_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);

```c++
int modbus_read_input_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);
```

 用于读远程设备的 addr 地址开始的共nb 位(输入寄存器)的状态。读取结果以uint(16 位) 的形式存储在dest数组中。

您必须注意分配足够的内存以将结果存储在dest位置，至少是nb* sizeof(uint16_t) 的内存大小。

该函数使用0x04 函数代码(读取输入寄存器)。保持寄存器和输入寄存器具有曾经具有不同的意义, 但现在通常只使用保持寄存器。

返回：成功返回读取输入位的数目即nb，失败返回-1并设置errno为Too many bits requested。

 

### 读取控制器(controller)描述  

int modbus_report_slave_id(modbus_t *ctx, int max_dest, uint8_t *dest);

```c++
int modbus_report_slave_id(modbus_t *ctx, int max_dest, uint8_t *dest);
//例子
uint8_t tab_bytes[MODBUS_MAX_PDU_LENGTH];

...

rc = modbus_report_slave_id(ctx, MODBUS_MAX_PDU_LENGTH, tab_bytes);
if(rc > 1) {
    printf("Run Status Indicator: %s\n", tab_bytes[1] ? "ON" : "OFF");
}
```

用于向控制器发送请求以获取控制器描述。

存储在dest中的响应包括：

从机(slave)ID ,此ID实际上完全不是唯一的，所以不能靠它来知道信息在响应中如何打包。

运行指示器状态(0x00 = OFF, 0xFF = ON)

特定于每个控制器的附加数据，例如： libmodbus 以字符串形式返回库的版本号。

此函数返回最多max_dest字节数据到dest,所以要确保dest空间足够。

返回：成功读取数据的数量，如果输出因为max_dest限制而被截断，则返回值会返回若dest空间足够情况下应该会写入到dest的字节数，因此，大于max_dest的返回值意味着响应数据被截断。失败返回-1并设置errno。

## 写数据

### 写一位数据(强置单线圈)

int modbus_write_bit(modbus_t *ctx, int addr, int status);

```c++
int modbus_write_bit(modbus_t *ctx, int addr, int status);
```

用于写远程设备addr地址处的状态，值必须是TRUE或者FLASE。

该函数使用0x05功能码(强置单线圈)。

返回：成功返回1，失败返回-1并设置errno。

### 写单寄存器(预置单寄存器)

int modbus_write_register(modbus_t *ctx, int addr, int value);

```c++
int modbus_write_register(modbus_t *ctx, int addr, int value);
```

用于写远程设备addr地址处的数值，设置为value。

该函数使用0x06功能码(预置单寄存器)。

返回：成功返回1，失败返回-1并设置errno。

### 写多位数据(强置多线圈)

int modbus_write_bits(modbus_t *ctx, int addr, int nb, const uint8_t *src);

```c++
int modbus_write_bits(modbus_t *ctx, int addr, int nb, const uint8_t *src);
```

将nb位(线圈) 的状态从src中写入远程设备地址addr,src数组必须包含设置为TRUE或FALSE的字节.

该函数使用0x0F功能码(强置多线圈)

返回：成功返回写入位数nb，失败返回-1并设置errno。

### 写多寄存器(预置多寄存器)

int modbus_write_registers(modbus_t *ctx, int addr, int nb, const uint16_t *src);

```c++
int modbus_write_registers(modbus_t *ctx, int addr, int nb, const uint16_t *src);
```

用于将src数组中的内容写到远程设备addr地址处的一组nb个寄存器。

该函数使用0x16功能码(预置多寄存器)。

返回：成功返回写入寄存器个数nb，失败返回-1并设置errno。

## 写和读数据

### 在单个处理中写入和读取多个寄存器

int modbus_write_and_read_registers(modbus_t *ctx, int write_addr, int write_nb, const uint16_t *src, int read_addr, int read_nb, const uint16_t *dest);

```c++
int modbus_write_and_read_registers(modbus_t *ctx, int write_addr, int write_nb, const uint16_t *src, int read_addr, int read_nb, const uint16_t *dest);
```

将src数组中的内容写到远程设备write_addr地址处的一组write_nb个寄存器，然后读取read_addr处的一组read_nb个寄存器内容并保存到dest数组。

该函数使用0x17 函数代码(写/读寄存器)。

返回：如果成功, 该函数应返回读取寄存器的数目。否则, 将返回-1 并设置 errno为：Too many registers requested, Too many registers to write。

## 原始请求

### 发送原始请求 

int modbus_send_raw_request(modbus_t *ctx, uint8_t *raw_req, int raw_req_length);

```c++
int modbus_send_raw_request(modbus_t *ctx, uint8_t *raw_req, int raw_req_length);
//例子
modbus_t *ctx;
/* Read 5 holding registers from address 1 */
uint8_t raw_req[] = { 0xFF, MODBUS_FC_READ_HOLDING_REGISTERS, 0x00, 0x01, 0x0, 0x05 };
int req_length;
uint8_t rsp[MODBUS_TCP_MAX_ADU_LENGTH];

ctx = modbus_new_tcp("127.0.0.1", 1502);
if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}

req_length = modbus_send_raw_request(ctx, raw_req, 6 * sizeof(uint8_t));
modbus_receive_confirmation(ctx, rsp);

modbus_close(ctx);
modbus_free(ctx);
```

通过在ctx环境下的套接口(socket)发送请求，此函数只用于调试，你必须小心的提出有效的请求，此函数只会添加到消息、所选后端的报头或者CRC(the header or CRC of the selected backend)，, 因此raw_req必须启动并包含至少一个从站/单元的ID和一个函数代码。此函数可用于发送未由库处理的请求。

libmodbus 的公共标头提供了支持的MODBUS_FC_函数代码的列表, 前缀为MODBUS_FC_READ_HOLDING_REGISTERS, 以帮助建立原始请求。

返回：完整的消息长度，计算与后端有关的额外数据。否则，它将返回- 1并设置errno。

### 收到确认请求 

int modbus_receive_confirmation(modbus_t *ctx, uint8_t *rsp);

```c++
int modbus_receive_confirmation(modbus_t *ctx, uint8_t *rsp);
//例子
uint8_t rsp[MODBUS_MAX_ADU_LENGTH];
rc = modbus_receive_confirmation(ctx, rsp);
```

通过在ctx环境下的套接口(socket)接受请求，此函数只用于调试，因为不会根据初试请求检查接受到的响应，此函数可用于接受未由库处理的请求。

响应的最大大小取决于使用的后端, 在 RTU 中,rsp必须是MODBUS_RTU_MAX_ADU_LENGTH字节, 在 TCP 中必须是MODBUS_TCP_MAX_ADU_LENGTH字节。如果要编写与两者兼容的代码, 可以使用常量MODBUS_MAX_ADU_LENGTH(所有 libmodbus 后台的最大值)。注意分配足够的内存以存储响应以避免服务器崩溃。

返回：将确认请求存储于rsp中，并在成功是返回响应长度，如果忽略指示请求，返回的请求长度可以是0(例如，在RTU模式下对另一个从机slave的查询)。否则返回-1并设置errno。

## 回复异常

### 发送一个异常响应

*int modbus_reply_exception(modbus_t *ctx, const uint8_t *req, unsigned int exception_code);

```c++
*int modbus_reply_exception(modbus_t *ctx, const uint8_t *req, unsigned int exception_code);
```

基于参数中的exception_code发送异常响应。

libmodbus 提供了以下异常代码:

1. `MODBUS_EXCEPTION_ILLEGAL_FUNCTION ` 
2.  `MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS ` 
3.  `MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE ` 
4.  `MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE ` 
5.  `MODBUS_EXCEPTION_ACKNOWLEDGE ` 
6.  `MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY ` 
7.  `MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE ` 
8.  `MODBUS_EXCEPTION_MEMORY_PARITY ` 
9.  `MODBUS_EXCEPTION_NOT_DEFINED ` 
10.  `MODBUS_EXCEPTION_GATEWAY_PATH ` 
11.  `MODBUS_EXCEPTION_GATEWAY_TARGET ` 

建立有效的响应需要初始请求req。

返回：成功则返回发送响应的长度，否则返回-1并设置errno为The exception code is invalid。

# 从机(服务器server)

服务器(server)等待来自于客户端(client)的请求,并且必须在收到请求的时候回答，libmodbus 提供以下功能来处理请求:

## 数据映射

### 分配位(线圈)和寄存器的数组

modbus_mapping_t modbus_mapping_new(int nb_bits, int nb_input_bits, int nb_registers, intnb_input_registers);

```c++
modbus_mapping_t modbus_mapping_new(int nb_bits, int nb_input_bits, int nb_registers, int nb_input_registers);

//例子
/* The fist value of each array is accessible from the 0 address. */
mb_mapping = modbus_mapping_new(BITS_ADDRESS + BITS_NB,
                                INPUT_BITS_ADDRESS + INPUT_BITS_NB,
                                REGISTERS_ADDRESS + REGISTERS_NB,
                                INPUT_REGISTERS_ADDRESS + INPUT_REGISTERS_NB);
if(mb_mapping == NULL) {
    fprintf(stderr, "Failed to allocate the mapping: %s\n",
            modbus_strerror(errno));
    modbus_free(ctx);
    return -1;
}
```

分配四数组来存储位(译者：线圈)、输入位、(保持)寄存器和输入寄存器。指针存储在 modbus_mapping_t 结构中。数组的所有值都初始化为零。

如果没有必要为特定类型的数据分配数组, 则可以在参数中传递零值, 关联的指针将赋值为 NULL。

此函数便于处理在服务器/从机中的请求。(译者注:在modbus中，server(服务器)和slave(从站)含义相同，client(客户端)和master(主站)含义相同)。

返回：成功，则返回新分配的结构，否则返回NULL并设置errno为Not enough memory。

### 释放modbus_mapping_t 结构

void modbus_mapping_free(modbus_mapping_t *mb_mapping);

```c++
void modbus_mapping_free(modbus_mapping_t *mb_mapping);
```

释放 mb_mapping_t 结构的4个数组， 最后由mb_mapping引用的 mb_mapping_t。

## 接收

### 收到指示请求 

int modbus_receive(modbus_t *ctx, uint8_t *req);

```c++
int modbus_receive(modbus_t *ctx, uint8_t *req);
```

从ctx环境socket接收指示请求,该函数由服务器接收并分析主机/客户端发送的指示请求。

如果需要使用其他套接字或文件描述符, 而不是在ctx环境中定义的, 请参阅函数modbus_set_socket(3).

返回：将指示请求存储到req中，并返回请求长度。否则返回-1并设置errno。

## 回复

### 响应收到的请求

int modbus_reply(modbus_t *ctx, const uint8_t *req, int req_length, modbus_mapping_t *mb_mapping);

```c++
int modbus_reply(modbus_t *ctx, const uint8_t *req, int req_length, modbus_mapping_t *mb_mapping);
```

对收到的请求进行响应，分析给定的req请求，然后使用ctx环境信息建立一个响应并发送。

如果请求指示读取或写入一个值，则操作会根据操作的数据类型在mb_mapping映射中执行。

如果发生错误, 将发送异常响应。

此功能是为 "服务器(从机)" 设计的。

返回：成功则返回响应的长度。否则返回-1并设置errno为Sending has failed，另外请参阅the errors returned by the syscall used to send the response(eg. send or write).

发送异常响应int modbus_reply_exception(modbus_t *ctx, const uint8_t *req, unsigned int exception_code);
int modbus_reply_exception(modbus_t *ctx, const uint8_t *req, unsigned int exception_code);
基于参数中的exception_code发送异常响应。

libmodbus 提供了以下异常代码:

1.  `MODBUS_EXCEPTION_ILLEGAL_FUNCTION` 
2.  `MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS` 
3.  `MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE` 
4.  `MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE` 
5.  `MODBUS_EXCEPTION_ACKNOWLEDGE` 
6.  `MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY` 
7.  `MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE` 
8.  `MODBUS_EXCEPTION_MEMORY_PARITY` 
9.  `MODBUS_EXCEPTION_NOT_DEFINED` 
10.  `MODBUS_EXCEPTION_GATEWAY_PATH ` 
11.  `MODBUS_EXCEPTION_GATEWAY_TARGET ` 

建立有效的响应需要初始请求要求。

返回：成功则返回发送的响应的长度，否则返回-1并设置errno为The exception code is invalid。

## 错误处理

libmodbus功能使用POSIX系统上的标准约定处理错误。一般来说，这意味着一旦发生故障，libmodbus函数将返回一个NULL值(如果返回一个指针)或一个负值(如果返回一个整数)，并且实际的错误代码将被存储在errno变量中。

提供modbus_strerror()函数将libmodbus特定的错误代码转换为错误消息字符串;

### 返回错误信息

const char *modbus_strerror(int errnum);

```
const char *modbus_strerror(int errnum);
//例子
if(modbus_connect(ctx) == -1) {
    fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
    abort();
}
```

会返回一个指向与errnum参数指定的错误号对应的错误消息字符串的指针。由于 libmodbus 定义了超出操作系统定义的其他错误号, 因此应用程序应该使用modbus_strerror()来优先于标准strerror()函数发送错误消息。

返回：返回一个指向错误消息字符串的指针。

# 杂项

该 `LIBMODBUS_VERSION_STRING` 表示libmodbus版本的程序已编译对应版本。变量 `libmodbus_version_major `， `libmodbus_version_minor`，`libmodbus_version_micro` 给出程序链接的版本。

# 版权协议

根据GNU通用公共许可证(LGPLv2.1 +)的条款，免费使用此软件。有关详细信息，请参阅COPYING.LESSERlibmodbus发行版随附的文件。
