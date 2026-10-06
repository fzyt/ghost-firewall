// 日志级别表。放模块级而不是写进模板表达式 —— 徽章配色和筛选按钮共用一份，
// 散在两处的话以后加级别一定会漏改一边。
// err/error、warn/warning 是同义的两个键（OpenWrt 用 err，别的用 error），
// 都留着，筛选按钮那边会按 label 去重。
const LOG_LEVELS = [
  { key: 'emerg',   label: '紧急', cls: 'bg-red-100 text-red-700' },
  { key: 'alert',   label: '严重', cls: 'bg-red-100 text-red-700' },
  { key: 'crit',    label: '致命', cls: 'bg-red-100 text-red-700' },
  { key: 'err',     label: '错误', cls: 'bg-red-100 text-red-700' },
  { key: 'error',   label: '错误', cls: 'bg-red-100 text-red-700' },
  { key: 'warn',    label: '警告', cls: 'bg-amber-100 text-amber-700' },
  { key: 'warning', label: '警告', cls: 'bg-amber-100 text-amber-700' },
  { key: 'notice',  label: '通知', cls: 'bg-blue-100 text-blue-700' },
  { key: 'info',    label: '信息', cls: 'bg-blue-100 text-blue-700' },
  { key: 'debug',   label: '调试', cls: 'bg-gray-100 text-gray-600' },
];

function app() {
  return {
    logLevels: LOG_LEVELS,
    // ======================= 认证状态 =======================
    auth: {
      authenticated: false,
      passwordSet: false,
      checking: true,         // 初次访问 /api/auth/status 期间为 true
      loginPassword: '',
      loginMode: 'login',     // 'login' | 'setup'
      loginLoading: false,
      loginError: '',
    },
    currentNav: 'network',
    navItems: [
      { id: 'network', label: '网络接口' },
      { id: 'knock', label: '端口敲门' },
      { id: 'ports', label: '端口转发' },
      { id: 'trust', label: '信任IP' },
      { id: 'logs', label: '日志开关' },
      { id: 'syslog', label: '系统日志' },
      { id: 'foreign', label: '国外IP拦截' },
      { id: 'dns-lan', label: 'DNS 局域网解析', icon: '🌐' },
      { id: 'ddns', label: 'DDNS' },
      { id: 'firewall', label: '防火墙规则' },
      { id: 'firewall-status', label: '防火墙状态', icon: '🛡️' },
      { id: 'lists', label: '名单管理', icon: '📋' },
      { id: 'reverse-proxy', label: '反代管理' },
      { id: 'intro', label: '功能介绍', icon: '📖' },
    ],
    config: {},
    logdConfig: {
      log_ip: '',
      log_port: '514',
      log_proto: 'tcp',
      log_size: 128,
      loading: false,
      saving: false,
    },
    whitelistTimeoutValue: 5,
    whitelistTimeoutUnit: 'h',
    loading: false,
    saving: false,
    applying: false,
    toast: { show: false, message: '', type: 'success' },

    // dry-run diff 弹窗
    diffModal: {
      show: false,
      loading: false,
      diff: null,    // {old_line_count, new_line_count, added_count, removed_count, added_sample, removed_sample, has_changes}
      risks: [],     // [{level, message}]
      newRulesText: '',
      pendingConfig: null,  // 用户确认后要提交的 config
    },

    // 网络配置（OpenWrt /etc/config/network）
    networkConfig: {
      lan_device: '',
      lan_proto: '',
      lan_ipaddr: '',
      lan_netmask: '',
      wan_device: '',
      wan_proto: '',
      wan_pppoe: false,
      wan_pppoe_username: '',
      wan_pppoe_password: '',
    },
    availableInterfaces: '',
    interfaceList: [],
    autoDetected: false,
    autoDetectedMessage: '',
    networkSaving: false,
    networkRestarting: false,
    rules: '',
    rulesLoading: false,
    chinaIpsInstalling: false,
    chinaIpsUpdating: false,
    ipv6Updating: false,
    fw4Active: false,
    nftablesLoaded: false,
    initExists: false,
    initEnabled: false,
    initHasFw4Stop: false,
    initUpToDate: false,
    repairing: false,

    ddnsTab: 'general',
    aliyunSubTab: 'setup',

    // 系统日志状态
    systemLogs: {
      allLogs: [],
      filteredLogs: [],
      sources: {},
      selectedSource: '',
      selectedLevels: [],
      searchKeyword: '',
      currentPage: 1,
      pageSize: 200,
      loading: false,
      buffer: null,
      unparsed: 0,
      authMerged: 0,
    },

    listsData: { whitelist: { ipv4: [], ipv6: [] }, blacklist: { ipv4: [], ipv6: [] } },
    listsLoading: false,
    listsNewIpWhitelist: '',
    listsNewIpBlacklist: '',
    // IP 预设 + 历史
    ipPresets: [],
    listHistory: [],
    presetModalOpen: false,
    presetEditing: null,     // {id, label, ip, type, auto_expire} 或 null（新建）
    presetSaving: false,
    presetSavingId: null,    // apply 时追踪哪个预设正在执行

    // 反代管理
    rpTab: 'rules',
    rp: {
      rules: [],
      certificates: [],
      settings: { http_redirect_enabled: true, hsts_enabled: true, tls_min_version: 'TLSv1.2', default_cert_id: '' },
      loading: false,
      dnsProviders: [],
      selectedDnsProvider: '',
      dnsCredentials: {},
    },
    rpEditingRule: null,
    rpUploading: false,
    rpUploadDomain: '',
    rpRequestDomain: '',

    ddns: {
      services: [],
      providers: [],
      ipv6Sources: [],
      ipv6Addresses: {},
      loaded: false,
      editingIndex: null,
      editingIsNew: false,
    },

    aliyun: {
      installed: false,
      configured: false,
      accessKeyId: '',
      accessKeySecret: '',
      regionId: 'cn-hangzhou',
      domain: '',
      records: [],
      localRecords: [],
      ipv6Sources: [],
      loading: false
    },

    async init() {
      // 监听全局 401 事件，api.request 在收到 401 时派发
      window.addEventListener('auth-expired', () => this.handleAuthExpired());
      window.addEventListener('auth-needs-setup', () => {
        this.auth.loginMode = 'setup';
      });

      // 第一步：检查认证状态。未登录时不加载任何业务数据
      await this.checkAuth();
      if (!this.auth.authenticated) return;

      await this.loadConfig();
      await this.loadNetworkConfig();
      await this.loadInterfaces();
      await this.loadLogdConfig();
      await this.loadFirewallStatus();
      await this.loadDdns();
    },

    async checkAuth() {
      try {
        const data = await api.get('/api/auth/status');
        // 后端 /api/auth/status 返回 {success, data:{...}} 双层结构（与
        // /api/reverse-proxy/status 等一致），而 api.request 只剥掉最外层的
        // success/message，直接读 data.authenticated 永远是 undefined。
        // 后果：password_set 读成 false → loginMode 误判成 'setup' → 已部署的
        // 面板首次打开显示的是「首次使用，请设置管理员密码」而不是登录框，
        // 用户输密码提交后后端 400「密码已设置，请用 /login 登录」——死循环。
        // 兼容双层与扁平两种风格。
        const d = (data && data.data) || data || {};
        this.auth.authenticated = !!d.authenticated;
        this.auth.passwordSet = !!d.password_set;
        this.auth.loginMode = d.password_set ? 'login' : 'setup';
      } catch (e) {
        // 401 说明未登录（虽然 status 端点本身放行，但保险起见）
        this.auth.authenticated = false;
        this.auth.passwordSet = false;
        this.auth.loginMode = 'setup';
      } finally {
        this.auth.checking = false;
      }
    },

    async doLogin() {
      if (!this.auth.loginPassword) {
        this.auth.loginError = '请输入密码';
        return;
      }
      this.auth.loginLoading = true;
      this.auth.loginError = '';
      try {
        await api.post('/api/auth/login', { password: this.auth.loginPassword });
        this.auth.authenticated = true;
        this.auth.loginPassword = '';
        // 登录成功后加载所有业务数据
        await this.loadAllData();
      } catch (e) {
        this.auth.loginError = e.message || '登录失败';
      } finally {
        this.auth.loginLoading = false;
      }
    },

    async doSetup() {
      if (!this.auth.loginPassword || this.auth.loginPassword.length < 4) {
        this.auth.loginError = '密码长度至少 4 位';
        return;
      }
      this.auth.loginLoading = true;
      this.auth.loginError = '';
      try {
        await api.post('/api/auth/setup', { password: this.auth.loginPassword });
        this.auth.authenticated = true;
        this.auth.passwordSet = true;
        this.auth.loginMode = 'login';
        this.auth.loginPassword = '';
        await this.loadAllData();
      } catch (e) {
        this.auth.loginError = e.message || '设置失败';
      } finally {
        this.auth.loginLoading = false;
      }
    },

    async doLogout() {
      try { await api.post('/api/auth/logout'); } catch (_) {}
      this.auth.authenticated = false;
      this.auth.loginPassword = '';
      // 清空敏感数据避免泄露（下次登录会重新加载）
      this.config = {};
      this.rp = { rules: [], certificates: [], settings: {} };
    },

    handleAuthExpired() {
      this.auth.authenticated = false;
      this.auth.loginError = '会话已过期，请重新登录';
      this.config = {};
      this.rp = { rules: [], certificates: [], settings: {} };
    },

    async loadAllData() {
      // 登录/初始化后批量加载所有数据
      try { await this.loadConfig(); } catch (_) {}
      try { await this.loadNetworkConfig(); } catch (_) {}
      try { await this.loadInterfaces(); } catch (_) {}
      try { await this.loadLogdConfig(); } catch (_) {}
      try { await this.loadFirewallStatus(); } catch (_) {}
      try { await this.loadDdns(); } catch (_) {}
      try { await this.loadReverseProxy(); } catch (_) {}
      // 规则预览走的是 x-init，而 x-init 在未登录时就被守卫挡掉了，
      // 登录后需要在这里补一次，否则进防火墙页看到的是空预览。
      try { await this.loadRules(); } catch (_) {}
    },

    // 改 log_size 会吃掉多少内存、能多装多少行。
    // 行长用当前缓冲区实测的平均值兜底（.224 实测 ≈86 字节/行），
    // 所以这是估算 —— 面板给的是区间，不是准数。
    //
    // 这里**返回预格式化好的字符串而不是数字**是有原因的，别改回去：
    // 模板里曾写成 x-show="pct !== null" + x-text="pct.toFixed(1)"，
    // 结果 x-show 只管显隐不管求值，mem_total 读不到时 pct 是 null，
    // 每次进这一页都抛 10 条 "Cannot read properties of null"，
    // 而且是页面级异常、按钮照样能点，不看控制台根本发现不了。
    // 把格式化收进方法里，模板就再也碰不到 null。
    logSizeEstimate(kb) {
      const kbNum = Number(kb) || 128;
      const per = this.systemLogs.buffer?.avg_bytes_per_line || 86;
      const memTotal = this.systemLogs.buffer?.mem_total_kb || 0;
      const lines = Math.round(kbNum * 1024 / per);
      const pct = memTotal ? (kbNum / memTotal * 100) : null;
      return {
        lines: lines.toLocaleString(),
        pctText: pct === null ? '' : pct.toFixed(1) + '%',
        warn: pct !== null && pct > 10,
      };
    },

    async loadLogdConfig() {
      try {
        const data = await api.get('/api/logd/config');
        this.logdConfig.log_ip = data.log_ip || '';
        this.logdConfig.log_port = data.log_port || '514';
        this.logdConfig.log_proto = data.log_proto || 'tcp';
        this.logdConfig.log_size = data.log_size || 128;
      } catch (e) {
        console.error('加载logd配置失败:', e);
      }
    },

    async saveLogdConfig() {
      // 保存会重启 log 服务，而重启会把内存环形缓冲清空
      // （.224 实测 1580 行 → 1 行）。这个副作用以前没有任何提示，
      // 用户保存完回头发现日志全没了却不知道是谁干的。
      // 注意只有真改了配置才重启（后端会比对），但事前先问一句最稳妥。
      if (!confirm(
        '保存后将重启 log 服务。\n\n' +
        '重启会清空本机内存里还没转发出去的历史日志。\n' +
        '（已配置远程转发的日志以远程服务器上保存的为准，不受影响。）\n\n' +
        '确定继续吗？'
      )) return;

      this.logdConfig.saving = true;
      try {
        // api.request 把 message 解构掉了，这里拿不到后端文案，
        // 所以按返回的结构化字段自己拼提示
        const r = await api.post('/api/logd/config', {
          log_ip: this.logdConfig.log_ip,
          log_port: this.logdConfig.log_port,
          log_proto: this.logdConfig.log_proto,
          log_size: this.logdConfig.log_size,
        });
        if (r.restarted) {
          this.showToast(
            `已保存，log 服务已重启（缓冲上限 ${r.log_size}KB）。本机历史日志已清空。`,
            'warning');
        } else {
          this.showToast('配置未变化，log 服务未重启，日志未清空', 'success');
        }
      } catch (e) {
        this.showToast('保存失败: ' + e.message, 'error');
      } finally {
        this.logdConfig.saving = false;
      }
    },

    async loadConfig() {
      this.loading = true;
      try {
        const data = await api.get('/api/config');
        delete data.success;
        this.config = data;
        if (this.config.china_ip_block === undefined) this.config.china_ip_block = false;
        if (this.config.dns_lan_resolver_enabled === undefined) this.config.dns_lan_resolver_enabled = false;
        if (!this.config.dns_lan_servers) this.config.dns_lan_servers = ['192.168.100.218'];
        if (this.config.dns_lan_log === undefined) this.config.dns_lan_log = false;
        if (!this.config.access_mode) this.config.access_mode = 'lan';
        if (!this.config.forward_rules || this.config.forward_rules.length === 0) {
          this.config.forward_rules = [];
        }
        // 从配置恢复白名单超时时间显示
        const wt = this.config.whitelist_timeout || 18000;
        if (wt % 3600 === 0) { this.whitelistTimeoutValue = wt / 3600; this.whitelistTimeoutUnit = 'h'; }
        else if (wt % 60 === 0) { this.whitelistTimeoutValue = wt / 60; this.whitelistTimeoutUnit = 'm'; }
        else { this.whitelistTimeoutValue = wt; this.whitelistTimeoutUnit = 's'; }
      } catch (e) {
        this.showToast('加载配置失败: ' + e.message, 'error');
        this.config = this.config || {};
        if (!this.config.forward_rules) this.config.forward_rules = [];
        if (!this.config.lan_allowed_ports) this.config.lan_allowed_ports = '';
        if (!this.config.access_mode) this.config.access_mode = 'lan';
        if (!this.config.wan_pppoe) this.config.wan_pppoe = false;
        if (this.config.dns_lan_resolver_enabled === undefined) this.config.dns_lan_resolver_enabled = false;
        if (!this.config.dns_lan_servers) this.config.dns_lan_servers = ['192.168.100.218'];
        if (this.config.dns_lan_log === undefined) this.config.dns_lan_log = false;
      } finally {
        this.loading = false;
      }
    },

    async saveConfig() {
      const multipliers = { s: 1, m: 60, h: 3600 };
      const timeoutSeconds = this.whitelistTimeoutValue * (multipliers[this.whitelistTimeoutUnit] || 1);
      if (timeoutSeconds <= 0) {
        this.showToast('超时时间必须大于0', 'error');
        return;
      }
      this.config.whitelist_timeout = timeoutSeconds;

      // dry-run：先调 preview-changes 看 diff + 风险
      this.diffModal.pendingConfig = { ...this.config };
      this.diffModal.loading = true;
      this.diffModal.show = true;
      this.diffModal.diff = null;
      this.diffModal.risks = [];
      this.diffModal.newRulesText = '';
      try {
        const data = await api.post('/api/rules/preview-changes',
          { proposed: this.config });
        this.diffModal.diff = data.diff;
        this.diffModal.risks = data.risks || [];
        this.diffModal.newRulesText = data.new_rules_text || '';
      } catch (e) {
        this.diffModal.show = false;
        this.showToast('预览失败: ' + e.message, 'error');
        return;
      } finally {
        this.diffModal.loading = false;
      }
      // 弹窗打开，等用户点"确认保存"或"取消"
    },

    async confirmSaveConfig() {
      const cfg = this.diffModal.pendingConfig;
      if (!cfg) return;
      this.saving = true;
      try {
        // 显式传 confirm=true，让后端知道前端已经看过预览+风险弹窗
        //（如果还有 critical 风险，后端会放行；普通 medium/high 风险也一并通过这里返回）
        const resp = await api.post('/api/config', { ...cfg, confirm: true });
        this.showToast('配置已保存', 'success');
        this.diffModal.show = false;
        this.diffModal.pendingConfig = null;
        // 如果保存路径检测到非 critical 风险，前端可选择提示（暂只用 toast 兜底）
        const risks = resp && resp.data && resp.data.risks ? resp.data.risks : [];
        if (risks.length > 0) {
          const high = risks.filter(r => r.level === 'high');
          if (high.length > 0) {
            this.showToast('已保存，但存在风险：' + high[0].message, 'error');
          }
        }
      } catch (e) {
        // 后端 409 CRITICAL_RISK：再次展示让用户二次确认
        if (e.code === 'CRITICAL_RISK' && e.data && e.data.data && Array.isArray(e.data.data.risks)) {
          const detail = e.data.data.risks.map(r => `[${r.level}] ${r.message}`).join('\n');
          if (!confirm('后端检测到 critical 风险：\n\n' + detail + '\n\n是否仍然保存？')) {
            this.saving = false;
            return;
          }
          // 用户再次确认，重试
          try {
            await api.post('/api/config', { ...cfg, confirm: true });
            this.showToast('配置已保存', 'success');
            this.diffModal.show = false;
            this.diffModal.pendingConfig = null;
          } catch (e2) {
            this.showToast('保存失败: ' + e2.message, 'error');
          }
        } else {
          this.showToast('保存失败: ' + e.message, 'error');
        }
      } finally {
        this.saving = false;
      }
    },

    cancelSaveConfig() {
      this.diffModal.show = false;
      this.diffModal.pendingConfig = null;
      this.diffModal.diff = null;
      this.diffModal.risks = [];
      this.showToast('已取消保存', 'info');
    },

    async restoreConfig() {
      try {
        const data = await api.post('/api/config/restore');
        alert(data.message || '配置已恢复');
        await this.loadConfig();
        await this.loadRules();
      } catch(e) {
        alert(e.message || '恢复失败');
      }
    },

    async applyRules() {
      this.applying = true;
      try {
        const data = await api.post('/api/rules/apply');
        this.showToast(data.message || '规则已应用', 'success');
        await this.loadRules();
        await this.loadFirewallStatus();
      } catch (e) {
        this.showToast('应用失败: ' + e.message, 'error');
      } finally {
        this.applying = false;
      }
    },

    togglePppoe() {
      this.networkConfig.wan_pppoe = !this.networkConfig.wan_pppoe;
      if (this.networkConfig.wan_pppoe) {
        this.config.wan_if = 'pppoe-wan';
      } else {
        this.config.wan_if = this.networkConfig.wan_device || '';
      }
      this.showToast('已切换 PPPoE，请保存防火墙配置以使更改生效');
    },

    async loadInterfaces() {
      try {
        const data = await api.get('/api/network/interfaces');
        this.interfaceList = data.interfaces || [];
        this.availableInterfaces = this.interfaceList.map(i => i.name).join(', ');
      } catch (e) {
        console.error('加载接口列表失败:', e);
      }
    },

    async loadNetworkConfig() {
      try {
        const data = await api.get('/api/network/config');
        delete data.success;

        // 自动识别并填入 networkConfig
        this.networkConfig = {
          lan_device: data.lan_device || '',
          lan_proto: data.lan_proto || '',
          lan_ipaddr: data.lan_ipaddr || '',
          lan_netmask: data.lan_netmask || '',
          wan_device: data.wan_device || '',
          wan_proto: data.wan_proto || '',
          wan_pppoe: data.wan_pppoe || false,
          wan_pppoe_username: data.wan_pppoe_username || '',
          wan_pppoe_password: data.wan_pppoe_password || '',
        };

        // nftables wan_if：PPPoE 时固定 pppoe-wan，否则用 network 中的设备
        if (this.networkConfig.wan_pppoe) {
          this.config.wan_if = 'pppoe-wan';
        } else if (this.networkConfig.wan_device) {
          this.config.wan_if = this.networkConfig.wan_device;
        }
        if (data.lan_device) {
          this.config.lan_if = data.lan_device;
        }
        if (data.lan_ipaddr && !this.config.router_ip4) {
          this.config.router_ip4 = data.lan_ipaddr;
        }
        if (data.lan_ip6 && !this.config.router_ip6) {
          this.config.router_ip6 = data.lan_ip6;
        }

        this.autoDetected = true;
        this.autoDetectedMessage = '已从 OpenWrt 网络配置自动填入';
      } catch (e) {
        console.error('加载网络配置失败:', e);
      }
    },

    async saveNetworkConfig() {
      this.networkSaving = true;
      try {
        await api.post('/api/network/config', this.networkConfig);
        this.showToast('网络配置已保存', 'success');
      } catch (e) {
        if (e.code === 'RULES_NOT_APPLIED') {
          alert(e.message);
        } else {
          this.showToast('保存失败: ' + e.message, 'error');
        }
      } finally {
        this.networkSaving = false;
      }
    },

    async restartNetwork() {
      if (!confirm('重启网络会短暂断开连接，确定继续？')) return;
      this.networkRestarting = true;
      try {
        await api.post('/api/network/restart');
        this.showToast('网络已重启，防火墙规则已重新应用', 'success');
      } catch (e) {
        this.showToast('重启失败: ' + e.message, 'error');
      } finally {
        this.networkRestarting = false;
      }
    },

    async loadSystemLogs() {
      this.systemLogs.loading = true;
      try {
        const data = await api.get('/api/system/logs?lines=20000');
        // 后端已经按 epoch 倒序排好了，这里**不要**再 reverse()
        // （原来那版前端 reverse 是因为后端返回的是 logread 的正序，
        //  后端改掉之后这行 reverse 会把顺序整个翻反，且没有任何报错）
        this.systemLogs.allLogs = data.logs || [];
        this.systemLogs.sources = data.sources || {};
        this.systemLogs.buffer = data.buffer || null;
        this.systemLogs.unparsed = data.unparsed || 0;
        this.systemLogs.authMerged = data.auth_merged || 0;
        this.systemLogs.currentPage = 1;
        // 不清空筛选条件：刷新日志时用户往往正是想继续看刚才筛出来的那批
        this.applyLogFilter();
      } catch (e) {
        this.showToast('加载日志失败: ' + e.message, 'error');
      } finally {
        this.systemLogs.loading = false;
      }
    },

    applyLogFilter() {
      const sl = this.systemLogs;
      const levels = sl.selectedLevels;
      const kw = (sl.searchKeyword || '').toLowerCase().trim();

      sl.filteredLogs = sl.allLogs.filter(l => {
        if (sl.selectedSource && l.source !== sl.selectedSource) return false;
        if (levels.length && !levels.includes(l.level)) return false;
        if (kw) {
          // 认证事件的指纹字段也纳入搜索 —— 查审计时最常见的问题是
          // 「这台设备什么时候来过」，只搜 message 的话 device/fp 永远搜不到。
          const hay = [l.message, l.source, l.ts, l.level,
                       l.device, l.fp, l.ip, l.user, l.event, l.uri]
            .filter(Boolean).join(' ').toLowerCase();
          if (!hay.includes(kw)) return false;
        }
        return true;
      });
      sl.currentPage = 1;
    },

    toggleLogLevel(level) {
      const a = this.systemLogs.selectedLevels;
      const i = a.indexOf(level);
      if (i >= 0) a.splice(i, 1); else a.push(level);
      this.applyLogFilter();
    },

    clearLogFilters() {
      this.systemLogs.selectedSource = '';
      this.systemLogs.selectedLevels = [];
      this.systemLogs.searchKeyword = '';
      this.applyLogFilter();
    },

    // 各级别计数，给筛选按钮上的角标用
    get logLevelCounts() {
      const c = {};
      for (const l of this.systemLogs.allLogs) {
        c[l.level] = (c[l.level] || 0) + 1;
      }
      return c;
    },

    // 只列出数据里真实出现过的级别，并按 label 去重：
    // err 和 error 同义，全列出来会出现两个「错误」按钮而其中一个恒为 0。
    get logLevelsPresent() {
      const counts = this.logLevelCounts;
      return LOG_LEVELS
        .filter(x => counts[x.key])
        .filter((x, i, arr) => arr.findIndex(y => y.label === x.label) === i)
        .map(x => ({ ...x, count: counts[x.key] }));
    },

    levelCls(level) {
      const hit = LOG_LEVELS.find(x => x.key === level);
      return hit ? hit.cls : 'bg-gray-100 text-gray-600';
    },

    levelLabel(level) {
      const hit = LOG_LEVELS.find(x => x.key === level);
      return hit ? hit.label : level;
    },

    // ISO 2026-10-06T18:52:41 → 10-06 18:52:41。
    // 日志表列宽紧张，全 ISO 太长；完整值放 title 里，鼠标悬停能看全。
    logTimeShort(iso) {
      if (!iso || iso.length < 19) return iso || '';
      return iso.slice(5, 10) + ' ' + iso.slice(11, 19);
    },

    // 缓冲区水位文案。缓冲写满后 logread 只会返回上限内的内容 ——
    // 原来 UI 无条件显示"共 N 条"，用户看不出 N 是全量还是被截断了。
    get logBufferText() {
      const b = this.systemLogs.buffer;
      if (!b) return '';
      if (!b.log_size_kb) return `缓冲区 ${b.total_lines} 行（log_size 未设置）`;
      const pct = Math.min(100, b.used_pct || 0);
      return `${b.log_size_kb} KB · 已用 ${pct}% · 约 ${b.total_lines} 行`
        + ` / 上限约 ${b.est_capacity_lines} 行`;
    },

    exportLogs(format) {
      const rows = this.systemLogs.filteredLogs;
      if (!rows.length) {
        this.showToast('当前筛选结果为空，没有可导出的内容', 'error');
        return;
      }

      const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
      const total = this.systemLogs.allLogs.length;
      let blob, name;

      if (format === 'json') {
        blob = new Blob([JSON.stringify(rows, null, 2)],
                        { type: 'application/json;charset=utf-8' });
        name = `nftables-logs-${stamp}.json`;
      } else {
        // 所有字段加引号、内部引号翻倍：日志消息里逗号和引号都很常见
        // （DHCPACK 那类），不转义导出的文件在 Excel 里直接串列。
        const COLS = ['ts', 'level', 'source', 'kind', 'facility', 'pid',
                      'message', 'event', 'ip', 'user', 'device', 'fp', 'uri'];
        const q = v => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
        const csv = [COLS.join(',')]
          .concat(rows.map(r => COLS.map(c => q(r[c])).join(',')))
          .join('\r\n');
        // 前置 BOM：没有它 Excel 会按本地代码页解码，中文全是乱码
        blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
        name = `nftables-logs-${stamp}.csv`;
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      // 立刻 revoke 会让部分浏览器下载到空文件，推迟一拍
      setTimeout(() => URL.revokeObjectURL(url), 1000);

      const scope = rows.length < total ? `（筛选后，共 ${total} 条）` : '';
      this.showToast(`已导出 ${rows.length} 条${scope}`, 'success');
    },

    getLogTotalPages() {
      return Math.max(1, Math.ceil(this.systemLogs.filteredLogs.length / this.systemLogs.pageSize));
    },

    // 当前页日志（getter computed）。避免 x-for 表达式里内联 slice 在 Alpine 3 的
    // reactivity 时序下出现"页码显示但内容空"的 bug。
    get currentLogPage() {
      const start = (this.systemLogs.currentPage - 1) * this.systemLogs.pageSize;
      const end = start + this.systemLogs.pageSize;
      return this.systemLogs.filteredLogs.slice(start, end);
    },

    goToLogPage(page) {
      if (page >= 1 && page <= this.getLogTotalPages()) {
        this.systemLogs.currentPage = page;
      }
    },

        async loadDdns() {
      try {
        const [config, providers, ipv6Sources] = await Promise.all([
          api.get('/api/ddns/config'),
          api.get('/api/ddns/providers'),
          api.get('/api/ddns/ipv6-sources')
        ]);
        const c = config.data || config;
        const prov = providers.data || providers;
        const ipv6s = ipv6Sources.data || ipv6Sources;
        this.ddns.services = c.services || [];
        this.ddns.providers = prov.providers || [];
        this.ddns.ipv6Sources = ipv6s.sources || [];
        this.ddns.ipv6Addresses = c.ipv6_addresses || {};
        this.ddns.loaded = true;
      } catch (e) {
        this.showToast('加载DDNS配置失败: ' + e.message, 'error');
    }
  },

  getProviderName(id) {
    const p = this.ddns.providers.find(p => p.id === id);
    return p ? p.name : id;
  },

  getIpv6SourceName(id) {
    const s = this.ddns.ipv6Sources.find(s => s.id === id);
    return s ? s.name : id;
  },

  editDdnsService(index) {
    this.ddns.editingIndex = index;
    this.ddns.editingIsNew = false;
    this.$nextTick(() => { this.ddns.editingIndex = index; });
  },

  saveDdnsService(index) {
    this.ddns.editingIndex = null;
    this.ddns.editingIsNew = false;
    this.saveDdns();
  },

  addDdnsService() {
    this.ddns.services.push({
      name: String(this.ddns.services.length + 1),
      enabled: false,
      service_name: this.ddns.providers[0]?.id || 'cloudflare.com-v4',
      sub_domain: '',
      main_domain: '',
      username: '',
      password: '',
      password_masked: true,
      interface: 'wan',
      use_ipv6: false,
      ip_source: 'network',
      ip_network: 'wan',
      param_enc: '',
      param_opt: '',
      ipv6_source: '',
      check_interval: 10
    });
    this.ddns.editingIndex = this.ddns.services.length - 1;
    this.ddns.editingIsNew = true;
    this.$nextTick(() => { this.ddns.editingIndex = this.ddns.services.length - 1; });
  },

  cancelDdnsEdit() {
    if (this.ddns.editingIsNew) {
      this.ddns.services.pop();
    }
    this.ddns.editingIndex = null;
    this.ddns.editingIsNew = false;
  },

  removeDdnsService(index) {
    if (confirm('确定删除此DDNS记录？')) {
      this.ddns.services.splice(index, 1);
      this.saveDdns();
    }
  },

  async saveDdns() {
    this.saving = true;
    try {
      await api.post('/api/ddns/save', { services: this.ddns.services });
      this.showToast('DDNS配置已保存', 'success');
      this.loadDdns();
    } catch (e) {
      this.showToast('保存失败: ' + e.message, 'error');
    } finally {
      this.saving = false;
    }
  },

  async restartDdns() {
    if (!confirm('确定重启DDNS服务？')) return;
    try {
      const data = await api.post('/api/ddns/restart');
      this.showToast(data.message || 'DDNS服务已重启', 'success');
    } catch (e) {
      this.showToast('重启失败: ' + e.message, 'error');
    }
  },

  async showDdnsStatus() {
    try {
      const data = await api.post('/api/ddns/status');
      this.showToast(data.message || (data.running ? 'DDNS服务运行中' : 'DDNS服务未运行'));
    } catch (e) {
      this.showToast('获取状态失败: ' + e.message, 'error');
    }
  },

  async loadAliyunStatus() {
    try {
      const data = await api.get('/api/aliyun-ddns/status');
      const cfg = (data.config || data);
      this.aliyun.installed = data.cli_installed || false;
      this.aliyun.configured = data.cli_configured || false;
      this.aliyun.accessKeyId = cfg.access_key_id || '';
      this.aliyun.regionId = cfg.region_id || 'cn-hangzhou';
      this.aliyun.domain = cfg.domain || '';
      // 复用 IPv6 来源
      if (!this.ddns.loaded) await this.loadDdns();
      this.aliyun.ipv6Sources = this.ddns.ipv6Sources;
      // 加载本地保存的记录
      if (data.records && data.records.length > 0) {
        this.aliyun.localRecords = data.records;
        this.aliyun.records = data.records;
      }
    } catch (e) {
      // 404 means not set up yet
      this.aliyun.installed = false;
    }
  },

  async setupAliyun() {
    this.aliyun.loading = true;
    try {
      await api.post('/api/aliyun-ddns/setup', {
        access_key_id: this.aliyun.accessKeyId,
        access_key_secret: this.aliyun.accessKeySecret,
        region_id: this.aliyun.regionId,
        domain: this.aliyun.domain
      });
      this.aliyun.installed = true;
      this.aliyun.configured = true;
      this.showToast('阿里云 DDNS 配置完成', 'success');
    } catch (e) {
      this.showToast('配置失败: ' + e.message, 'error');
    } finally {
      this.aliyun.loading = false;
    }
  },

  async loadAliyunRecords() {
    this.aliyun.loading = true;
    try {
      const data = await api.get('/api/aliyun-ddns/records');
      this.aliyun.records = data.records || [];
      this.aliyun.localRecords = data.localRecords || [];
      // 复用 IPv6 来源
      if (!this.ddns.loaded) await this.loadDdns();
      this.aliyun.ipv6Sources = this.ddns.ipv6Sources;
    } catch (e) {
      this.showToast('获取记录失败: ' + e.message, 'error');
    } finally {
      this.aliyun.loading = false;
    }
  },

  getAliyunRecordEnabled(index) {
    const rr = this.aliyun.records[index]?.RR || this.aliyun.records[index]?.rr || '';
    const type = this.aliyun.records[index]?.Type || this.aliyun.records[index]?.type || '';
    const local = this.aliyun.localRecords.find(r => r.rr === rr && r.type === type);
    return local ? local.enabled : false;
  },

  getAliyunRecordIpv6Source(index) {
    const rr = this.aliyun.records[index]?.RR || this.aliyun.records[index]?.rr || '';
    const type = this.aliyun.records[index]?.Type || this.aliyun.records[index]?.type || '';
    const local = this.aliyun.localRecords.find(r => r.rr === rr && r.type === type);
    return local ? (local.ipv6_source || '') : '';
  },

  setAliyunRecordIpv6Source(index, value) {
    const rr = this.aliyun.records[index]?.RR || this.aliyun.records[index]?.rr || '';
    const type = this.aliyun.records[index]?.Type || this.aliyun.records[index]?.type || '';
    let local = this.aliyun.localRecords.find(r => r.rr === rr && r.type === type);
    if (!local) {
      local = { rr, type, enabled: false, ipv6_source: '' };
      this.aliyun.localRecords.push(local);
    }
    local.ipv6_source = value;
  },

  toggleAliyunRecord(index) {
    const rr = this.aliyun.records[index]?.RR || this.aliyun.records[index]?.rr || '';
    const type = this.aliyun.records[index]?.Type || this.aliyun.records[index]?.type || '';
    let local = this.aliyun.localRecords.find(r => r.rr === rr && r.type === type);
    if (!local) {
      local = { rr, type, enabled: false, ipv6_source: '' };
      this.aliyun.localRecords.push(local);
    }
    local.enabled = !local.enabled;
  },

  async saveAliyunConfig() {
    this.aliyun.loading = true;
    try {
      // 以 records（阿里云 API 完整数据）为基础，合并 localRecords 的 enabled/ipv6_source
      const localMap = {};
      for (const l of this.aliyun.localRecords) {
        localMap[l.rr + ':' + l.type] = l;
      }
      const mergedRecords = this.aliyun.records.map(r => {
        const rr = r.RR || r.rr || '';
        const type = r.Type || r.type || '';
        const local = localMap[rr + ':' + type];
        if (local) {
          return { ...r, enabled: local.enabled, ipv6_source: local.ipv6_source };
        }
        return { ...r };
      });
      // 如果 localRecords 中有 records 里没有的（新增），也加入
      for (const l of this.aliyun.localRecords) {
        const key = l.rr + ':' + l.type;
        if (!this.aliyun.records.some(r => (r.RR || r.rr) === l.rr && (r.Type || r.type) === l.type)) {
          mergedRecords.push({ ...l, Type: l.type, Value: l.value || '', RecordId: l.record_id || '' });
        }
      }
      await api.post('/api/aliyun-ddns/save', { records: mergedRecords });
      this.showToast('阿里云 DDNS 配置已保存', 'success');
    } catch (e) {
      this.showToast('保存失败: ' + e.message, 'error');
    } finally {
      this.aliyun.loading = false;
    }
  },

    async loadLists() {
      this.listsLoading = true;
      try {
        const [whitelist, blacklist, presets, history] = await Promise.all([
          api.get('/api/lists/whitelist'),
          api.get('/api/lists/blacklist'),
          api.get('/api/lists/presets').catch(() => ({ presets: [] })),
          api.get('/api/lists/history?limit=20').catch(() => ({ history: [] })),
        ]);
        this.listsData.whitelist = { ipv4: whitelist.allowed4 || {}, ipv6: whitelist.allowed6 || {} };
        this.listsData.blacklist = { ipv4: blacklist.blacklist4 || {}, ipv6: blacklist.blacklist6 || {} };
        this.ipPresets = presets.presets || [];
        this.listHistory = history.history || [];
      } catch (e) {
        this.showToast('加载名单失败: ' + e.message, 'error');
      } finally {
        this.listsLoading = false;
      }
    },

    async loadListPresets() {
      try {
        const data = await api.get('/api/lists/presets');
        this.ipPresets = data.presets || [];
      } catch (e) {
        console.warn('加载预设失败:', e);
      }
    },

    async loadListHistory() {
      try {
        const data = await api.get('/api/lists/history?limit=20');
        this.listHistory = data.history || [];
      } catch (e) {
        console.warn('加载历史失败:', e);
      }
    },

    openPresetModal(preset) {
      if (preset) {
        this.presetEditing = { ...preset };
      } else {
        this.presetEditing = { id: '', label: '', ip: '', type: 'whitelist', auto_expire: true };
      }
      this.presetModalOpen = true;
    },

    closePresetModal() {
      this.presetModalOpen = false;
      this.presetEditing = null;
    },

    async savePreset() {
      const p = this.presetEditing;
      if (!p || !p.label || !p.ip) {
        this.showToast('标签和 IP 不能为空', 'error');
        return;
      }
      this.presetSaving = true;
      try {
        if (p.id) {
          await api.put('/api/lists/presets/' + p.id, {
            label: p.label, ip: p.ip, type: p.type, auto_expire: p.auto_expire,
          });
          this.showToast('预设已更新', 'success');
        } else {
          await api.post('/api/lists/presets', {
            label: p.label, ip: p.ip, type: p.type, auto_expire: p.auto_expire,
          });
          this.showToast('预设已添加', 'success');
        }
        this.closePresetModal();
        await this.loadListPresets();
      } catch (e) {
        this.showToast('保存失败: ' + e.message, 'error');
      } finally {
        this.presetSaving = false;
      }
    },

    async deletePreset(preset) {
      if (!confirm('删除预设「' + (preset.label || preset.ip) + '」？\n\n注意：这不会从 nft set 里移除已加入的 IP。')) return;
      try {
        await api.delete('/api/lists/presets/' + preset.id);
        this.showToast('预设已删除', 'success');
        await this.loadListPresets();
      } catch (e) {
        this.showToast('删除失败: ' + e.message, 'error');
      }
    },

    async applyPreset(preset) {
      this.presetSavingId = preset.id;
      try {
        await api.post('/api/lists/presets/' + preset.id + '/apply');
        this.showToast('已加入「' + preset.label + '」', 'success');
        // 刷新：set 数据 + 预设 active 状态 + 历史
        await Promise.all([this.loadLists(), this.loadListPresets(), this.loadListHistory()]);
      } catch (e) {
        this.showToast('加入失败: ' + e.message, 'error');
      } finally {
        this.presetSavingId = null;
      }
    },

    async clearListHistory() {
      if (!confirm('清空名单操作历史？\n\n注意：这不影响 nft set 里当前的 IP。')) return;
      try {
        await api.post('/api/lists/history/clear');
        this.listHistory = [];
        this.showToast('历史已清空', 'success');
      } catch (e) {
        this.showToast('清空失败: ' + e.message, 'error');
      }
    },

    getListSetName(type, ip) {
      const prefix = type === 'whitelist' ? 'allowed' : 'blacklist';
      return prefix + (ip.includes(':') ? '6' : '4');
    },

    getMergedListIps(type) {
      const list = this.listsData[type];
      if (!list) return [];
      const entries = [];
      for (const [ip, expires] of Object.entries(list.ipv4)) entries.push({ ip, expires });
      for (const [ip, expires] of Object.entries(list.ipv6)) entries.push({ ip, expires });
      return entries;
    },

    formatExpires(expires) {
      if (expires === null) return '永久';
      if (!expires) return '-';
      return expires;
    },

    async addToList(type) {
      const ipKey = type === 'whitelist' ? 'listsNewIpWhitelist' : 'listsNewIpBlacklist';
      const ip = this[ipKey].trim();
      if (!ip) return;
      try {
        const setName = this.getListSetName(type, ip);
        await api.post('/api/lists/add', { set_name: setName, ip });
        this[ipKey] = '';
        await this.loadLists();
        this.showToast('已添加: ' + ip, 'success');
      } catch (e) {
        this.showToast('添加失败: ' + e.message, 'error');
      }
    },

    async deleteFromList(type, ip) {
      // 二次确认：名单里的每一项删除按钮都该有。
      // 原来只有 flushList / deletePreset / deleteRpRule / removeDdnsService 有，
      // 唯独这个直接就发请求了 —— 白名单里往往是管理机和 NAS 等关键地址，
      // 手滑删掉一条的后果比删一条 DDNS 记录大得多。
      const label = type === 'whitelist' ? '白名单' : '黑名单';
      if (!confirm(`确定从${label}中删除 ${ip} 吗？`)) return;
      try {
        const setName = this.getListSetName(type, ip);
        await api.post('/api/lists/delete', { set_name: setName, ip });
        await this.loadLists();
        this.showToast('已删除: ' + ip, 'success');
      } catch (e) {
        this.showToast('删除失败: ' + e.message, 'error');
      }
    },

    async flushList(type) {
      const label = type === 'whitelist' ? '白名单' : '黑名单';
      if (!confirm('确定清空' + label + '？')) return;
      try {
        const prefix = type === 'whitelist' ? 'allowed' : 'blacklist';
        await Promise.all([
          api.post('/api/lists/flush', { set_name: prefix + '4' }),
          api.post('/api/lists/flush', { set_name: prefix + '6' }),
        ]);
        await this.loadLists();
        this.showToast(label + '已清空', 'success');
      } catch (e) {
        this.showToast('清空失败: ' + e.message, 'error');
      }
    },

    async loadFirewallStatus() {
      try {
        const data = await api.get('/api/firewall/status');
        this.fw4Active = data.fw4_active;
        this.nftablesLoaded = data.nftables_loaded;
        this.initExists = data.init_exists;
        this.initEnabled = data.init_enabled;
        this.initHasFw4Stop = data.init_has_fw4_stop;
        this.initUpToDate = data.init_up_to_date;
      } catch(e) {}
    },

    async repairInitScript() {
      this.repairing = true;
      try {
        const data = await api.post('/api/firewall/repair-init');
        this.showToast(data.message || 'init 脚本已修复', 'success');
        await this.loadFirewallStatus();
      } catch (e) {
        this.showToast('修复失败: ' + e.message, 'error');
      } finally {
        this.repairing = false;
      }
    },

  showToast(message, type = 'success') {
      this.toast = { show: true, message, type };
      setTimeout(() => { this.toast.show = false; }, 3000);
    },

    addForwardRule() {
      this.config.forward_rules.push({ tcp_ports: '', udp_ports: '', target_ip: '', target_ipv6: '' });
    },

    removeForwardRule(index) {
      this.config.forward_rules.splice(index, 1);
    },

    async loadRules() {
      // Alpine 的 x-init 不管 x-show 是否为 true 都会执行，所以未登录时
      // 页面一加载这里就被调用 → /api/rules/preview 401 → api.request 派发
      // 全局 auth-expired → handleAuthExpired() 把 config/rp 清空并弹出
      // 「会话已过期，请重新登录」。用户还没输密码就被告知会话过期。
      // 守卫放在方法里而不是 x-init 里，这样页面上的「刷新预览」按钮也一并受保护。
      if (!this.auth.authenticated) return;
      this.rulesLoading = true;
      try {
        const data = await api.get('/api/rules/preview');
        this.rules = data.rules || '';
      } catch (e) {
        this.rules = '加载失败: ' + e.message;
      } finally {
        this.rulesLoading = false;
      }
    },

    async installChinaIps() {
      if (!confirm('将下载中国IP列表并配置自动更新（每周一次），首次可能需要1-2分钟，继续？')) return;
      this.chinaIpsInstalling = true;
      try {
        const data = await api.post('/api/firewall/install-china-ips');
        this.showToast(data.message || '安装完成', 'success');
      } catch (e) {
        this.showToast('安装失败: ' + e.message, 'error');
      } finally {
        this.chinaIpsInstalling = false;
      }
    },

    async updateIpv6() {
      this.ipv6Updating = true;
      try {
        const data = await api.post('/api/network/update-ipv6');
        this.showToast(data.message || 'IPv6 刷新完成', 'success');
      } catch (e) {
        this.showToast(e.message || 'IPv6 刷新失败', 'error');
      } finally {
        this.ipv6Updating = false;
      }
    },

    async updateChinaIps() {
      if (!confirm('立即刷新中国IP集合？')) return;
      this.chinaIpsUpdating = true;
      try {
        const data = await api.post('/api/firewall/update-china-ips');
        this.showToast(data.message || '刷新完成', 'success');
      } catch (e) {
        this.showToast('刷新失败: ' + e.message, 'error');
      } finally {
        this.chinaIpsUpdating = false;
      }
    },

    // ===== 反代管理 =====
    async loadReverseProxy() {
      this.rp.loading = true;
      try {
        const [rules, certs, settings] = await Promise.all([
          api.get('/api/reverse-proxy/rules').catch(() => ({ rules: [] })),
          api.get('/api/reverse-proxy/certificates').catch(() => ({ certificates: [] })),
          api.get('/api/reverse-proxy/settings').catch(() => null)
        ]);
        this.rp.rules = (rules.data || rules).rules || [];
        this.rp.certificates = (certs.data || certs).certificates || [];
        // 只有一个证书时自动设为默认
        if (this.rp.certificates.length === 1 && !this.rp.settings.default_cert_id) {
          await this.setDefaultCert(this.rp.certificates[0].id);
        }
        if (settings) {
          const s = settings.data || settings;
          this.rp.settings = {
            http_redirect_enabled: s.http_redirect_enabled !== undefined ? s.http_redirect_enabled : true,
            hsts_enabled: s.hsts_enabled !== undefined ? s.hsts_enabled : true,
            tls_min_version: s.tls_min_version || 'TLSv1.2',
            default_cert_id: s.default_cert_id || ''
          };
        }
        await this.loadDnsProviders();
      } catch (e) {
        this.showToast('加载反代配置失败: ' + e.message, 'error');
      } finally {
        this.rp.loading = false;
      }
    },

    async loadDnsProviders() {
      try {
        const data = await api.get('/api/reverse-proxy/dns-providers');
        this.rp.dnsProviders = data.data.providers || [];
        // 自动选中阿里云（如果存在）
        if (this.rp.dnsProviders.length > 0 && !this.rp.selectedDnsProvider) {
          this.selectDnsProvider(this.rp.dnsProviders[0].id);
        }
      } catch(e) {}
    },

    selectDnsProvider(providerId) {
      this.rp.selectedDnsProvider = providerId;
      if (providerId === 'ali') {
        this.rp.dnsCredentials = {};
        return;
      }
      const provider = this.rp.dnsProviders.find(p => p.id === providerId);
      if (provider && provider.saved_credentials) {
        this.rp.dnsCredentials = { ...provider.saved_credentials };
      } else if (provider && provider.fields) {
        this.rp.dnsCredentials = {};
        provider.fields.forEach(f => { this.rp.dnsCredentials[f.key] = ''; });
      } else {
        this.rp.dnsCredentials = {};
      }
    },

    saveRpRule() {
      const rule = { ...this.rpEditingRule };
      // lookup cert domain
      if (rule.ssl_cert_id) {
        const cert = this.rp.certificates.find(c => c.id == rule.ssl_cert_id);
        if (cert) {
          rule.certificate_domain = cert.domain;
          rule.certificate_days_remaining = cert.days_remaining;
        }
      }
      if (rule._editIndex !== undefined) {
        this.rp.rules[rule._editIndex] = rule;
        delete rule._editIndex;
      } else {
        this.rp.rules.push(rule);
      }
      this.rpEditingRule = null;
      this.saveRpRules();
    },

    editRpRule(index) {
      this.rpEditingRule = { ...this.rp.rules[index], _editIndex: index };
    },

    async deleteRpRule(index) {
      if (!confirm('确定删除此反代规则？')) return;
      const rule = this.rp.rules[index];
      // 如果有 id，先调用后端删除
      if (rule.id) {
        try {
          await api.delete('/api/reverse-proxy/rules/' + rule.id);
        } catch (e) {
          this.showToast('删除失败: ' + e.message, 'error');
          return;
        }
      }
      this.rp.rules.splice(index, 1);
      this.showToast('规则已删除', 'success');
    },

    async saveRpRules() {
      this.rp.loading = true;
      try {
        // Save rules one by one: existing rules use PUT, new rules use POST
        // 注意：POST 必须回写后端返回的 rule_id 到 rp.rules[i].id，否则下次保存会重复创建
        for (let i = 0; i < this.rp.rules.length; i++) {
          const { _editIndex, ...clean } = this.rp.rules[i];
          if (clean.id) {
            await api.put('/api/reverse-proxy/rules/' + clean.id, clean);
          } else {
            const resp = await api.post('/api/reverse-proxy/rules', clean);
            // api.request 已解构 {success, message, ...data}，resp 就是 data
            if (resp && resp.rule_id) {
              this.rp.rules[i].id = resp.rule_id;  // 同步后端分配的 id
            }
          }
        }
        this.showToast('反代规则已保存', 'success');
        // auto reload nginx
        try {
          await api.post('/api/reverse-proxy/nginx/reload');
          this.showToast('Nginx 已重载', 'success');
        } catch (e) {
          this.showToast('规则已保存，但 Nginx 重载失败: ' + e.message, 'error');
        }
      } catch (e) {
        this.showToast('保存失败: ' + e.message, 'error');
      } finally {
        this.rp.loading = false;
      }
    },

    async testRpRule(rule) {
      try {
        const data = await api.post('/api/reverse-proxy/rules/' + (rule.id || rule.domain) + '/test');
        this.showToast(data.message || '连通性测试成功', 'success');
      } catch (e) {
        this.showToast('测试失败: ' + e.message, 'error');
      }
    },

    async testNginxConfig() {
      this.rp.loading = true;
      try {
        const data = await api.post('/api/reverse-proxy/nginx/test');
        this.showToast(data.message || 'Nginx 配置测试通过', 'success');
      } catch (e) {
        this.showToast('配置测试失败: ' + e.message, 'error');
      } finally {
        this.rp.loading = false;
      }
    },

    async reloadNginx() {
      this.rp.loading = true;
      try {
        const data = await api.post('/api/reverse-proxy/nginx/reload');
        this.showToast(data.message || 'Nginx 已重载', 'success');
      } catch (e) {
        this.showToast('重载失败: ' + e.message, 'error');
      } finally {
        this.rp.loading = false;
      }
    },

    async uploadRpCert() {
      if (!this.rpUploadDomain.trim()) { this.showToast('请输入域名', 'error'); return; }
      const certFile = this.$refs.rpCertFile?.files?.[0];
      const keyFile = this.$refs.rpKeyFile?.files?.[0];
      if (!certFile || !keyFile) { this.showToast('请选择证书和私钥文件', 'error'); return; }
      this.rpUploading = true;
      try {
        const fd = new FormData();
        fd.append('domain', this.rpUploadDomain);
        fd.append('cert_file', certFile);
        fd.append('key_file', keyFile);
        const resp = await fetch('/api/reverse-proxy/certificates/upload', { method: 'POST', body: fd });
        const json = await resp.json();
        if (json.success === false) throw new Error(json.message || '上传失败');
        // 后端会在同 domain 已有 manual 证书时自动复用 id，replaced=true 表示"原地续期"
        const replaced = json.data && json.data.replaced === true;
        this.showToast(replaced ? '已替换同域名旧证书（引用关系保留）' : '证书上传成功', 'success');
        this.rpUploadDomain = '';
        if (this.$refs.rpCertFile) this.$refs.rpCertFile.value = '';
        if (this.$refs.rpKeyFile) this.$refs.rpKeyFile.value = '';
        await this.loadReverseProxy();
      } catch (e) {
        this.showToast('上传失败: ' + e.message, 'error');
      } finally {
        this.rpUploading = false;
      }
    },

    async requestRpCert() {
      if (!this.rpRequestDomain.trim()) { this.showToast('请输入域名', 'error'); return; }
      if (!this.rp.selectedDnsProvider) { this.showToast('请选择 DNS 提供商', 'error'); return; }
      this.rpUploading = true;
      try {
        const body = {
          domain: this.rpRequestDomain,
          dns_provider: this.rp.selectedDnsProvider,
        };
        if (this.rp.selectedDnsProvider !== 'ali') {
          body.dns_credentials = this.rp.dnsCredentials;
        }
        const data = await api.post('/api/reverse-proxy/certificates/request', body);
        this.showToast(data.message || '证书申请成功', 'success');
        this.rpRequestDomain = '';
        await this.loadReverseProxy();
      } catch (e) {
        this.showToast('申请失败: ' + e.message, 'error');
      } finally {
        this.rpUploading = false;
      }
    },

    async renewRpCert(cert) {
      if (!confirm('确定续期 ' + (cert.domain || '') + ' 的证书？')) return;
      this.rpUploading = true;
      try {
        const data = await api.post('/api/reverse-proxy/certificates/' + cert.id + '/renew');
        this.showToast(data.message || '证书续期成功', 'success');
        await this.loadReverseProxy();
      } catch (e) {
        this.showToast('续期失败: ' + e.message, 'error');
      } finally {
        this.rpUploading = false;
      }
    },

    async deleteRpCert(cert) {
      if (!confirm('确定删除 ' + (cert.domain || '') + ' 的证书？')) return;
      this.rpUploading = true;
      try {
        await api.delete('/api/reverse-proxy/certificates/' + cert.id);
        this.showToast('证书已删除', 'success');
        await this.loadReverseProxy();
      } catch (e) {
        // 证书被反代规则引用时，后端返回 400 + referenced_by + hint
        const detail = e.data && e.data.data;
        if (detail && Array.isArray(detail.referenced_by) && detail.referenced_by.length > 0) {
          const rules = detail.referenced_by.map(r => r.domain).join(', ');
          const useForce = confirm(
            `证书被 ${detail.referenced_by.length} 条反代规则引用（${rules}）。\n\n` +
            `要先上传一个同域名的新证书，让旧证书的引用自动迁移到新证书吗？\n\n` +
            `点击「确定」跳转到上传区，点击「取消」自己处理引用关系。`
          );
          if (useForce) {
            this.rpTab = 'certs';
            this.rpUploadDomain = cert.domain || '';
            // 滚动到上传区（顶部）
            const uploadSection = document.querySelector('[x-ref="rpCertFile"]');
            if (uploadSection) {
              const card = uploadSection.closest('.bg-gray-50');
              if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            this.showToast('请上传同域名的新证书（fullchain + privkey），将自动替换旧证书', 'info');
          }
          return;
        }
        this.showToast('删除失败: ' + e.message, 'error');
      } finally {
        this.rpUploading = false;
      }
    },

    async downloadRpCert(cert) {
      if (!confirm('将下载 ' + (cert.domain || '') + ' 的证书（含私钥），请妥善保管。\n\n继续？')) return;
      this.rpUploading = true;
      try {
        const resp = await fetch('/api/reverse-proxy/certificates/' + cert.id + '/download');
        if (!resp.ok) {
          let msg = '下载失败';
          try {
            const j = await resp.json();
            if (j && j.message) msg = j.message;
          } catch (_) {}
          throw new Error(msg);
        }
        // 从 Content-Disposition 解析文件名，回退默认
        let filename = (cert.domain || cert.id) + '.zip';
        const disp = resp.headers.get('Content-Disposition') || '';
        const m = disp.match(/filename="?([^"]+)"?/);
        if (m) filename = m[1];
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        this.showToast('证书已下载', 'success');
      } catch (e) {
        this.showToast('下载失败: ' + e.message, 'error');
      } finally {
        this.rpUploading = false;
      }
    },

    async setDefaultCert(certId) {
      try {
        const data = await api.post('/api/reverse-proxy/certificates/' + certId + '/set-default');
        this.rp.settings.default_cert_id = certId;
        this.showToast((data.data && data.data.message) || '已设为默认证书', 'success');
      } catch (e) {
        this.showToast('设置失败: ' + e.message, 'error');
      }
    },

    getRpDefaultCert() {
      if (!this.rp.settings.default_cert_id) return null;
      return this.rp.certificates.find(c => c.id == this.rp.settings.default_cert_id);
    },

    getRpCertDaysClass(days) {
      if (days === undefined || days === null) return 'text-gray-600';
      if (days <= 0) return 'text-red-600 font-medium';
      if (days < 30) return 'text-orange-500';
      return 'text-gray-600';
    },

    getRpCertStatusText(days) {
      if (days === undefined || days === null) return '-';
      if (days <= 0) return '🔴 已过期';
      return '● 有效';
    },

    async saveRpSettings() {
      this.rp.loading = true;
      try {
        await api.post('/api/reverse-proxy/settings', this.rp.settings);
        this.showToast('全局设置已保存', 'success');
      } catch (e) {
        this.showToast('保存失败: ' + e.message, 'error');
      } finally {
        this.rp.loading = false;
      }
    },
  };
}

const api = {
  async request(url, options = {}) {
    let resp;
    try {
      resp = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options });
    } catch (e) {
      const err = new Error('网络请求失败: ' + (e.message || e));
      throw err;
    }

    // 401 未登录：派发全局事件，前端 Alpine 监听后跳登录页
    if (resp.status === 401) {
      let body = null;
      try { body = await resp.json(); } catch (_) {}
      window.dispatchEvent(new CustomEvent('auth-expired', { detail: { url } }));
      const err = new Error((body && body.message) || '未登录');
      err.code = (body && body.code) || 'AUTH_REQUIRED';
      err.data = body;
      err.status = 401;
      throw err;
    }

    // 429 限流：提示用户等待
    if (resp.status === 429) {
      let body = null;
      try { body = await resp.json(); } catch (_) {}
      const retryAfter = resp.headers.get('Retry-After') || '?';
      const err = new Error((body && body.message) || `操作过于频繁，请 ${retryAfter} 秒后再试`);
      err.code = (body && body.code) || 'RATE_LIMITED';
      err.retryAfter = parseInt(retryAfter, 10) || 0;
      throw err;
    }

    const json = await resp.json();
    if (json.success === false) {
      const err = new Error(json.message || '请求失败');
      err.code = json.code;
      err.data = json;
      throw err;
    }
    const { success, message, ...data } = json;
    return data;
  },
  get(url) { return this.request(url); },
  post(url, body) { return this.request(url, { method: 'POST', body: JSON.stringify(body) }); },
  put(url, body) { return this.request(url, { method: 'PUT', body: JSON.stringify(body) }); },
  delete(url) { return this.request(url, { method: 'DELETE' }); }
};

// ============================================================
// x-cloak 兜底清除
// ============================================================
// Alpine 3 自带 x-cloak 指令（alpine.js 里 d("cloak", ...removeAttribute("cloak"))），
// 配合 styles.css 的 [x-cloak]{display:none!important} 用来防首屏闪烁。
// 但 3.15.8 实测：该指令没有真的把 x-cloak 属性摘掉，元素上属性一直在。
// 后果很严重 —— 那条 !important 会把带 x-cloak 的元素永久钉死：
//   登录遮罩 <div x-show="!auth.authenticated && !auth.checking" x-cloak>
// 在未登录时表达式为 true、x-show 也没错，却因为 x-cloak 残留而一直 display:none，
// 用户既看不到登录框、又处于未认证态（接口全部 401）—— 页面直接死锁。
//
// 这里在 Alpine 初始化完成后统一清一遍。alpine:initialized 是 Alpine 3 自身保证
// 会派发的事件；再挂一个 load 兜底，防止个别环境下该事件没派发。
const _stripCloak = () => {
  document.querySelectorAll('[x-cloak]').forEach((el) => el.removeAttribute('x-cloak'));
};
document.addEventListener('alpine:initialized', _stripCloak);
window.addEventListener('load', _stripCloak);
