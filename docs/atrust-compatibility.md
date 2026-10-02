# aTrust 部署兼容配置

每个 aTrust Profile 独立保存 `atrust_compatibility`，默认所有兜底关闭。
选项不按学校或控制器域名自动开启。AnyConnect Profile 拒绝非空 aTrust 选项。

创建 JSON 配置，例如 `atrust-compatibility.json`：

```json
{
  "fallback_app_id": "",
  "fallback_gateways": [],
  "gateway_server_name": "",
  "missing_gateway_group_fallback": false,
  "tcp_to_l3_fallback": true
}
```

通过 CLI 导入到新配置或替换现有配置：

```sh
flexconnect profile add --provider atrust --auth-method ecnu_passkey --keystore ./ecnu.keystore --atrust-compatibility-file ./atrust-compatibility.json campus https://vpn.ecnu.edu.cn
flexconnect profile update -p campus --atrust-compatibility-file ./atrust-compatibility.json
```

导入内容经本地 API 存入 Profile，日常连接不再读取导入文件。
修改源 JSON 后必须再次执行 `profile update`。连接中的配置变更会沿用现有清理和重连流程。
文件内容为 `{}` 时清空全部兼容选项；未传参数则保持原设置。
CLI、API 和状态文件使用相同字段。未知字段、非法地址或不完整进程身份会被拒绝。

| 字段 | 默认值 | 行为 |
| --- | --- | --- |
| `fallback_app_id` | 空 | 资源没有匹配时使用指定应用 ID，仍交由网关验证授权 |
| `fallback_gateways` | 空数组 | 控制器没有下发网关时使用，地址必须包含端口，支持 `[IPv6]:port` |
| `gateway_server_name` | 空 | 指定网关 TLS 证书域名，继续验证证书 |
| `missing_gateway_group_fallback` | `false` | 所选组没有地址时使用控制器的完整网关列表；不替换非空分组 |
| `tcp_to_l3_fallback` | `false` | 流式命令不支持或建立阶段提前关闭时尝试 L3；不覆盖认证/授权拒绝、不可达或取消 |
| `process_identity` | 省略 | 同时覆盖 TCP 和 L3 进程元数据，必须包含 `name`、`platform`、`path` |

ECNU 正常登录不需要开启这些兼容选项。上海科大旧部署的可选值：

```json
{
  "fallback_app_id": "681165d0-1c77-11ed-8650-cd35a51aa42a",
  "fallback_gateways": ["119.78.254.241:441", "59.78.171.241:441"],
  "gateway_server_name": "vpn.shanghaitech.edu.cn",
  "missing_gateway_group_fallback": true,
  "tcp_to_l3_fallback": true
}
```

按部署需求逐项启用；如控制器提供多个 CAS 域，还需显式设置 `--login-domain`。
进程元数据是协议参数，与宿主系统无关，不代表本机进程检测或可信状态。
诊断中的 `implemented_capabilities` 表示库实现范围，资源授权和实际连接结果仍分别判断。
