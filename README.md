# CF-IP 优化版

替换：
- `src/generator.py`
- `config/config.yml`

核心改动：
1. 地区别名映射：HKG→HK、LAX/SFO/SEA/ORD/DFW 等→US、SIN→SG、NRT/HND/TYO/KIX→JP、ICN/SEL→KR、TPE→TW、FRA/BER→DE。
2. 历史池增加地区最低库存：主要地区默认各保留 2 个。
3. 历史池上限从 30 提升到 60，避免地区节点过容易被全局淘汰。
4. 地区输出在历史池裁剪之前选择，因此历史健康节点可以真正作为当前运行的地区备用节点。
5. 所有配置地区都会生成对应的 `.txt` 和 `.yaml`；即使某地区本轮 0 节点，也会生成 `proxies: []` 的 YAML，避免 OpenClash Provider 因文件不存在而 404。
6. 历史记录加载和当前源合并时，会尽量用新的地区别名规则纠正旧的 OTHER。
7. 当前源暂时缺少地区标签时，不会立即用 OTHER 覆盖已有的明确历史地区。
8. 保留原有 WS 真实检测、IPv6 跳过测试、ISP 输出、all.txt/all.yaml 等主要功能。

建议第一次替换后手动运行一次 GitHub Actions，重点看：
- Region HK / JP / SG / KR / TW / US / DE
- `other` 数量
- `[HISTORY] final pool`
- 是否始终出现 `jp.yaml`

注意：本版本不会把一个失败节点当作健康备用节点；历史备用仍必须通过现有健康逻辑。IPv6 仍按原配置 `skip_ipv6_test: true` 处理。
