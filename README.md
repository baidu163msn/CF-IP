# CF VLESS Generator

独立于 BPB-Worker-Panel 的 VLESS 节点生成器。

## 功能

- 每 30 分钟从多个公开 IP/域名源拉取候选 `IP:PORT#备注` / `DOMAIN:PORT#备注`
- IPv4 / IPv6 解析
- `address + port` 去重
- 按 HK / JP / SG / KR / TW / US 等地区自动分类
- TCP 连接 + TLS SNI 健康检查
- 将通过测试的地址套入固定 VLESS WS + TLS 模板
- 生成 Base64 VLESS 订阅文本，可直接作为 Mihomo/OpenClash provider 的 HTTP URL
- GitHub Pages 自动发布
- `workflow_dispatch` 可手工立即运行

## 注意

当前健康检查验证的是 TCP + TLS/SNI，不是完整 VLESS 登录测试。
因此“测试通过”表示该 IP:PORT 对指定 TLS SNI 可建立连接，并不等于最终 VLESS 一定可用。
Mihomo/OpenClash 的节点 health-check 仍建议作为第二层实际网络环境筛选。

## GitHub Pages

仓库 Settings → Pages → Build and deployment → Source 选择 **GitHub Actions**。

部署后：
- `/all.txt`：全部 IP 节点
- `/hk.txt`：香港
- `/jp.txt`：日本
- `/sg.txt`：新加坡
- `/kr.txt`：韩国
- `/tw.txt`：台湾
- `/us.txt`：美国
- `/domain-asia.txt`：域名源节点

GitHub Actions 的 schedule 使用 UTC；当前使用 `7,37 * * * *`，即每小时第 7、37 分钟执行，约每 30 分钟一次。
