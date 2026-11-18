# ShadowLemon 出入站协议

本 fork 在 mihomo Alpha 分支上新增 `shadowlemon` 出入站协议，对接 ShadowLemon V0.2 加密代理（线版本字节 4）。协议实现位于 `transport/shadowlemon/`，与 Rust 参考实现按线格式互通。

## 出站（proxies）

```yaml
proxies:
  - name: sl
    type: shadowlemon
    server: 1.2.3.4
    port: 2027
    username: user1
    password: password1
    udp: true
    # mtu: 1400
    # deployment-secret: "..."   # 也可由环境变量 SHADOWLEMON_ENVELOPE_SECRET 提供
```

`DialContext` 建立 SOCKS5 CONNECT（TCP 目标经 UDP 上的用户态 ARQ 承载）；`ListenPacketContext` 建立 UDP ASSOCIATE。

## 入站（listeners）

```yaml
listeners:
  - name: sl-in
    type: shadowlemon
    port: 2029
    users:
      user1: password1
    # deployment-secret: "..."
```

服务端在单个 UDP socket 上接受 CONNECT 与 UDP ASSOCIATE，并把解密后的连接/数据报交给 mihomo tunnel。

## 部署密钥

`SHADOWLEMON_ENVELOPE_SECRET` 是必填的高熵共享秘密，两端必须一致：它派生 UDP 路由信封 keystream 与 user hint。未设置时可使用配置字段 `deployment-secret`。凭据经 `SHA256(password || 0x00 || username)` 后再哈希一次（与 Rust 两端一致），随后 PBKDF2-HMAC-SHA256 派生静态密钥。

## 互通性

已用以下组合验证：

- mihomo 出站 → Rust shadowlemon server：CONNECT 64KB HTTP 响应完整通过。
- Rust shadowlemon client → mihomo 入站：CONNECT 建立成功，数据经 tunnel 转发。

在纯 loopback 且无网络 pacing 的环境下，用户态 ARQ 偶发秒级尾延迟，可能让最后一个数据分段延迟到达（表现为 curl 在末尾少量字节处超时）。这是该 ARQ 实现的已知行为，在非 loopback 网络上不出现。

## 未实现的可选项

线协议类型 10/11 的低熵数据解码未实现（Rust 参考实现中同样默认关闭，配置层无开关）。两端均不产生该类型帧，不影响互通。
