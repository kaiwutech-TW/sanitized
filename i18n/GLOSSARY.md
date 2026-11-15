# Sanitized translation glossary

Source text is Traditional Chinese (Taiwan). Translations: English (`en`), Japanese (`ja`),
Simplified Chinese (`zh-Hans`, mainland usage). Use these terms everywhere so every page agrees.
For macOS features, use Apple's own wording in that language (System Settings, Finder, etc.).

## Style

- **en**: plain, short UI English. Sentence case for buttons and labels ("Move to Trash", not
  "Move To Trash"). No exclamation marks unless the source has one. Use "Mac" as Apple does.
- **ja**: です・ます for sentences and descriptions; short noun phrases for buttons and labels
  (「スキャン」「ゴミ箱に入れる」). Use full-width punctuation 「、。（）」 as the source does.
- **zh-Hans**: mainland vocabulary, not just converted characters (文件 not 檔案, 文件夹 not 資料夾,
  内存 not 記憶體, 程序/应用 not 程式, 设置 not 設定, 磁盘 not 磁碟, 软件 not 軟體, 网络 not 網路,
  默认 not 預設, 运行 not 執行, 加载 not 載入, 信息 not 資訊, 支持 not 支援, 窗口 not 視窗,
  用户 not 使用者, 账户 not 帳號, 视频 not 影片, 屏幕 not 螢幕, 菜单栏 not 選單列, 硬件 not 硬體,
  服务器 not 伺服器, 数据库 not 資料庫, 搜索 not 搜尋, 删除 not 刪除 (same), 卸载 not 解除安裝).
- Keep product and project names as is: Sanitized, Apple XProtect, MalwareBazaar, abuse.ch,
  Objective-See, OSV.dev, Docker, Homebrew, npm, Cargo, YARA, Mole, Spotlight, Time Machine,
  Finder, Safari, Chrome, iCloud, Xcode.
- Keep placeholders `{}` exactly as many as the source. You may reorder with `{0}`, `{1}` when
  the language needs a different word order.
- Keep line breaks (`\n`) where the source has them.

## Module and page names

| zh-Hant | en | ja | zh-Hans |
|---|---|---|---|
| Mac 狀態 | Mac Status | Mac の状態 | Mac 状态 |
| 一鍵健檢 | Quick Checkup | クイックチェック | 一键体检 |
| 垃圾清理 | Junk Cleanup | ジャンク削除 | 垃圾清理 |
| 安全防護 | Protection | セキュリティ保護 | 安全防护 |
| 效能最佳化 | Performance | パフォーマンス | 性能优化 |
| 應用程式 | Applications | アプリケーション | 应用程序 |
| 整理雜亂 | Clutter | 不要ファイル整理 | 整理杂乱 |
| 空間地圖 | Disk Map | ディスクマップ | 空间地图 |
| 雲端檔案 | Cloud Files | クラウドファイル | 云端文件 |
| Docker 清理 | Docker Cleanup | Docker クリーンアップ | Docker 清理 |
| 漏洞檢查 | Vulnerability Check | 脆弱性チェック | 漏洞检查 |
| 設定 | Settings | 設定 | 设置 |
| 模組 | Modules | モジュール | 模块 |
| 工具 | Tools | ツール | 工具 |
| 系統總覽 | Overview | 概要 | 系统总览 |

## Common terms

| zh-Hant | en | ja | zh-Hans |
|---|---|---|---|
| 掃描 | scan | スキャン | 扫描 |
| 清理 | clean up | クリーンアップ | 清理 |
| 移除 / 刪除 | remove / delete | 削除 | 移除 / 删除 |
| 垃圾桶 / 廢紙簍 | Trash | ゴミ箱 | 废纸篓 |
| 移到垃圾桶 / 移到廢紙簍 | Move to Trash | ゴミ箱に入れる | 移到废纸篓 |
| 隔離區 | Quarantine | 隔離領域 | 隔离区 |
| 還原 | restore | 復元 | 还原 |
| 即時防護 | real-time protection | リアルタイム保護 | 实时防护 |
| 即時監控 | real-time monitoring | リアルタイム監視 | 实时监控 |
| 惡意軟體 | malware | マルウェア | 恶意软件 |
| 廣告軟體 | adware | アドウェア | 广告软件 |
| 病毒碼 / 病毒碼來源 | malware signatures / signature sources | マルウェア定義 / 定義ソース | 病毒库 / 病毒库来源 |
| 規則 | rule | ルール | 规则 |
| 指紋 (檔案指紋) | fingerprint (file hash) | フィンガープリント（ハッシュ） | 指纹（文件哈希） |
| 威脅 | threat | 脅威 | 威胁 |
| 可疑 | suspicious | 不審な | 可疑 |
| 安全清單 | allow list | 許可リスト | 白名单 |
| 快速 / 平衡 / 深度 (掃描模式) | Quick / Balanced / Deep | クイック / バランス / ディープ | 快速 / 平衡 / 深度 |
| 漏洞 | vulnerability | 脆弱性 | 漏洞 |
| 套件 / 相依套件 | package / dependency | パッケージ / 依存パッケージ | 软件包 / 依赖包 |
| 相依清單 | dependency file (lockfile/manifest) | 依存関係ファイル | 依赖清单 |
| 嚴重 / 高 / 中 / 低 / 未評級 | Critical / High / Medium / Low / Unrated | 緊急 / 高 / 中 / 低 / 未評価 | 严重 / 高 / 中 / 低 / 未评级 |
| 修正版本 / 建議升級版本 | fixed version / suggested upgrade | 修正版 / 推奨アップグレード | 修复版本 / 建议升级版本 |
| 快取 | cache | キャッシュ | 缓存 |
| 記錄檔 | log files | ログファイル | 日志文件 |
| 偏好設定 | preferences | 環境設定 | 偏好设置 |
| 殘留檔案 | leftover files | 残りファイル | 残留文件 |
| 解除安裝 / 移除程式 | uninstall | アンインストール | 卸载 |
| 更新程式 | Updater | アップデート | 更新程序 |
| 安裝檔 | installers | インストーラ | 安装包 |
| 大型檔案 | large files | 大きなファイル | 大文件 |
| 重複檔案 | duplicates | 重複ファイル | 重复文件 |
| 檔案 | file | ファイル | 文件 |
| 資料夾 | folder | フォルダ | 文件夹 |
| 磁碟 / 磁碟空間 | disk / disk space | ディスク / ディスク容量 | 磁盘 / 磁盘空间 |
| 可用空間 | free space | 空き容量 | 可用空间 |
| 記憶體 | memory | メモリ | 内存 |
| 記憶體壓力 | memory pressure | メモリプレッシャー | 内存压力 |
| 虛擬記憶體 (swap) | swap | スワップ | 交换空间 |
| 處理器 / CPU | CPU | CPU | CPU |
| 健康分數 / 健康狀態 | health score / health | ヘルススコア / 健康状態 | 健康分数 / 健康状态 |
| 極佳 / 良好 / 普通 / 不佳 | Excellent / Good / Fair / Poor | 非常に良好 / 良好 / 普通 / 要注意 | 极佳 / 良好 / 一般 / 较差 |
| 維護任務 | maintenance tasks | メンテナンス | 维护任务 |
| 登入項目 / 背景項目 / 啟動項目 | login items / background items / launch items | ログイン項目 / バックグラウンド項目 / 起動項目 | 登录项 / 后台项目 / 启动项 |
| 啟動代理程式 (LaunchAgent) | launch agent | 起動エージェント | 启动代理 |
| 瀏覽器擴充功能 | browser extensions | ブラウザ機能拡張 | 浏览器扩展 |
| 隱私 | privacy | プライバシー | 隐私 |
| 應用程式權限 | app permissions | アプリのアクセス権 | 应用权限 |
| 完整磁碟取用權限 | Full Disk Access | フルディスクアクセス | 完全磁盘访问权限 |
| 系統設定 | System Settings | システム設定 | 系统设置 |
| 隱私權與安全性 | Privacy & Security | プライバシーとセキュリティ | 隐私与安全性 |
| 鑰匙圈 | Keychain | キーチェーン | 钥匙串 |
| 選單列 | menu bar | メニューバー | 菜单栏 |
| 活動監視器 | Activity Monitor | アクティビティモニタ | 活动监视器 |
| 管理者密碼 | administrator password | 管理者パスワード | 管理员密码 |
| 映像檔 / 容器 / 網路 / volume / 建置快取 (Docker) | images / containers / networks / volumes / build cache | イメージ / コンテナ / ネットワーク / ボリューム / ビルドキャッシュ | 镜像 / 容器 / 网络 / 卷 / 构建缓存 |
| 第 1 級 / 第 2 級 / 第 3 級 (Docker) | Level 1 / Level 2 / Level 3 | レベル 1 / 2 / 3 | 第 1 级 / 第 2 级 / 第 3 级 |
| 金鑰 | key | キー | 密钥 |
| 掃描中… / 正在… | Scanning… / …ing… | スキャン中… / …中… | 扫描中… / 正在… |
| 完成 | done | 完了 | 完成 |
| 停止 | Stop | 停止 | 停止 |
| 重新掃描 | Scan again | 再スキャン | 重新扫描 |
| 全部選取 / 全部取消 | Select all / Deselect all | すべて選択 / すべて解除 | 全选 / 取消全选 |
| 顯示 (在 Finder 中顯示) | Show (in Finder) | 表示（Finder で表示） | 显示（在访达中显示） |
| 個項目 | items | 項目 | 个项目 |
| 秒 / 分鐘 / 天 | s / min / days | 秒 / 分 / 日 | 秒 / 分钟 / 天 |
| 新 (sidebar badge) | New | 新 | 新 |
| 檢查新版本 | check for updates | アップデートを確認 | 检查新版本 |
| 跟隨系統 | Use system language | システムに合わせる | 跟随系统 |
