# Windows API 版: portproxy / Firewall 設定 (C++17)

`netsh.exe` を起動せず、以下に相当する処理を行う実装です。

```cmd
netsh interface portproxy add v4tov4 listenport=8180 connectaddress=x.x.x.x connectport=8080
netsh advfirewall firewall add rule name="proxy forward" dir=in action=allow protocol=TCP localport=8180
netsh interface portproxy delete v4tov4 listenport=8180 listenaddress=0.0.0.0
netsh advfirewall firewall delete rule name="proxy forward"
```

## 構成

- `WindowsNetworkConfig.h`: `INetworkConfiguration` 抽象インターフェースと設定モデル
- `WindowsNetworkConfig.cpp`: Win32 レジストリ API、SCM API、Windows Firewall COM API を用いた実装
- `main.cpp`: `add` と `delete` の実行例
- `CMakeLists.txt`: Windows / MSVC 向けビルド定義

## ビルド

Visual Studio の Developer PowerShell で以下を実行します。

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

または x64 Native Tools Command Prompt for VS から直接:

```cmd
cl /nologo /std:c++17 /EHsc /W4 /DUNICODE /D_UNICODE main.cpp WindowsNetworkConfig.cpp /link advapi32.lib ole32.lib oleaut32.lib ws2_32.lib
```

## 実行

**管理者権限**のターミナルで、転送先を実際の IPv4 アドレスに置き換えます。

```powershell
.\build\Release\network_rules.exe add 192.0.2.10
.\build\Release\network_rules.exe delete
```

`192.0.2.10` はドキュメント用 IP アドレスの例です。

## 設定結果の確認

```cmd
netsh interface portproxy show v4tov4
netsh advfirewall firewall show rule name="proxy forward"
netstat -ano | findstr :8180
```

## 注意点

- PortProxy のレジストリ形式は公開の管理 API ではなく、ProcMon で実測した実装依存形式です。Windows 更新後の互換性保証はありません。
- `RegSetValueExW` / `RegDeleteValueW` で `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` を変更し、`iphlpsvc` へ `SERVICE_CONTROL_PARAMCHANGE` を送信します。
- `listenaddress=0.0.0.0` を値名 `*/8180` として正規化します。削除時は古い手動設定 `0.0.0.0/8180` もフォールバックとして扱います。
- `INetFwRules::Add` は同名ルールを上書きする場合があるため、この実装では `Item` で既存名を検出した場合は例外にします。したがって既存ルールがある場合は `netsh add` と完全には同じ動作になりません。
- IPv4 アドレスは数値表現のみ対応します（`netsh` が対応するホスト名は非対応）。ポート範囲は 1〜65535 です。
- PortProxy / Firewall にまたがる完全なトランザクションはありません。Firewall の追加に失敗すると、直前に作成した PortProxy をベストエフォートで削除します。削除は双方を独立に試みます。
- `ControlService` の成功はサービスへの通知成功を意味し、通信可能性を保証しません。`iphlpsvc` が起動しており、転送先に到達できる必要があります。
- ルールは全プロファイルの TCP 8180 番への入力を許可し、全 IPv4 インターフェースでリッスンします。外部から到達可能になるため、実環境ではアクセス元アドレスの制限を検討してください。
- このサンプルは Windows 上でのビルド・実行による検証は未実施です。

## 根拠

- [Microsoft: netsh interface portproxy](https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh-interface-portproxy)
- [Microsoft: ControlService](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-controlservice)
- [Microsoft: INetFwRules::Add](https://learn.microsoft.com/windows/win32/api/netfw/nf-netfw-inetfwrules-add)
- [Microsoft: INetFwRules::Remove](https://learn.microsoft.com/windows/win32/api/netfw/nf-netfw-inetfwrules-remove)
- [Microsoft: Windows Firewall C++ sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/security/windowsfirewall)
- [Independent reverse engineering of PortProxy / iphlpsvc](https://adepts.of0x.cc/netsh-portproxy-code/)
