# GEO 基础数据与首次启动（2026-11-16）

正式 Android 包真机首次连接失败的日志为 `内核初始化超时：Can't find ASN.mmdb, start download`。调试安装已有 GEO 缓存，因而此前的连接回归没有覆盖这个条件。仅延长启动超时不能解决首次下载依赖问题。

## 其他客户端的做法

| 客户端 | 仓库证据 | 启动策略 |
| --- | --- | --- |
| Clash Meta for Android | [MainApplication.kt](https://github.com/MetaCubeX/ClashMetaForAndroid/blob/main/app/src/main/java/com/github/kr328/clash/MainApplication.kt) | 启动时把 APK assets 中的 GeoIP、GeoSite、ASN 和 BundleMRS 复制到内核目录；按应用更新时间处理旧文件。 |
| FlClash | [assets/data](https://github.com/chen08209/FlClash/tree/main/assets/data)、[pubspec.yaml](https://github.com/chen08209/FlClash/blob/main/pubspec.yaml)、[geo.go](https://github.com/chen08209/FlClash/blob/main/core/geo.go) | 安装包提供 ASN、GeoIP dat/metadb 和 GeoSite；资源更新单独执行，支持配置下载 URL。 |
| Clash Verge Rev | [init.rs](https://github.com/clash-verge-rev/clash-verge-rev/blob/main/src-tauri/src/utils/init.rs) | 初始化处理安装资源中的 Country.mmdb、ASN.mmdb、geoip.dat、geosite.dat。 |

三者都提供本地基础数据；不是让每个新用户先直连 GitHub 才能启动代理。更新策略和覆盖规则不同，不能照搬“每次升级覆盖所有文件”，否则可能破坏用户指定的数据源和分类。

## 中国网络环境下的选择

首次启动和后续更新应分开。内置经过校验的数据能消除基础 GEO 下载的网络前提；GitHub 或某个 CDN 的临时可用性不能成为首次启动条件。[Mihomo 文档](https://wiki.metacubex.one/config/general/#_18)提供自定义 `geox-url`、GEO 自动更新开关和适合小内存设备的默认 `memconservative` 加载器；文档示例也使用 jsDelivr，但这不证明某个公共 CDN 在所有地区、运营商都稳定。

Billow 保留订阅的 `geox-url` 以及已有下载源选择，不默认把用户的订阅地址发给第三方代理站。内置数据不是替代所有订阅资源：远程 proxy-provider、rule-provider 仍可能需要下载；自定义 GeoSite 分类必须使用包含该分类的数据源，不能静默删掉对应规则来“连接成功”。

## 本次 Android 实现

- 每次构建都先查询 MetaCubeX 官方数据仓库 release 分支的最新提交，再从该提交获取四份文件和官方校验值，保证同一个安装包的数据一致。`android-geo.json` 仅维护来源与文件列表，不固定数据版本；解析出的提交和校验值记录在包内 build.json，仅用于构建追溯，不在产品界面显示。
- 将 ASN、Country、GeoIP 和 GeoSite 放入 APK。内核启动前以流式 IO 释放缺失、零字节或缺少 MMDB 元数据尾部的文件；复用完整缓存，避免覆盖用户更新。
- 先写临时文件再改名，复制失败不留下被当成有效数据的半成品。不会一次把所有数据库加载到 Rust 堆内存。
- 前端明确显示“初始化内核和配置资源”与“建立 VPN”阶段，首次启用不再同时显示“选择一份配置后连接”。
- 单元回归覆盖无网络首次释放、零字节及中断 MMDB 恢复、保留用户更新和包资源缺失；正式包真机已验证从此前缺少/残缺 ASN 的状态恢复并成功连接。

这些文件增加的是安装包和磁盘占用。运行内存取决于内核实际加载的规则和数据，不能把文件大小直接当作 RAM，也不能据此声称达到 iOS 扩展的 50 MiB 限制。
