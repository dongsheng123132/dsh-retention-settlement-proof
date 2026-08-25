# dsh-retention-settlement-proof

面向 DeepSeek Harness 的离线、无正文“删除结算证明”：验证一条已录制的删除/保留请求是否在必需存储投影中完成，并在重启后持续缺席。

本插件**绝不执行删除**。它只读取显式、带哈希的请求、墓碑和缺席观察票据；任何复活、陈旧、缺面、仅重启前观察、身份或摘要不一致都会失败闭合。报告不含会话 ID、会话正文、原票据、路径或秘密。

```bash
dsh-retention-settlement-proof verify --workspace . --manifest proof.json --artifactDir artifacts
```

所有输入和输出都限制在显式 workspace，拒绝符号链接与路径逃逸；无网络、无子进程、无真实会话修改。
