function app() {
  return {
    currentNav: 'network',
    navItems: [
      { id: 'network', label: '网络接口' },
      { id: 'knock', label: '端口敲门' },
      { id: 'ports', label: '端口转发' },
      { id: 'trust', label: '信任IP' },
      { id: 'logs', label: '日志开关' },
      { id: 'syslog', label: '系统日志' },
      { id: 'foreign', label: '国外IP拦截' },
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
      loading: false,
      saving: false,
    },
    whitelistTimeoutValue: 5,
    whitelistTimeoutUnit: 'h',
    loading: false,
    saving: false,
    applying: false,
    toast: { show: false, message: '', type: 'success' },

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
      searchKeyword: '',
      currentPage: 1,
      pageSize: 200,
      loading: false,
    },

    listsData: { whitelist: { ipv4: [], ipv6: [] }, blacklist: { ipv4: [], ipv6: [] } },
    listsLoading: false,
    listsNewIpWhitelist: '',
    listsNewIpBlacklist: '',

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
      await this.loadConfig();
      await this.loadNetworkConfig();
      await this.loadInterfaces();
      await this.loadLogdConfig();
      await this.loadFirewallStatus();
      await this.loadDdns();
    },

    async loadLogdConfig() {
      try {
        const data = await api.get('/api/logd/config');
        this.logdConfig.log_ip = data.log_ip || '';
        this.logdConfig.log_port = data.log_port || '514';
        this.logdConfig.log_proto = data.log_proto || 'tcp';
      } catch (e) {
        console.error('加载logd配置失败:', e);
      }
    },

    async saveLogdConfig() {
      this.logdConfig.saving = true;
      try {
        await api.post('/api/logd/config', {
          log_ip: this.logdConfig.log_ip,
          log_port: this.logdConfig.log_port,
          log_proto: this.logdConfig.log_proto,
        });
        this.showToast('日志转发配置已保存，logd 服务已重启', 'success');
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
      this.saving = true;
      try {
        await api.post('/api/config', this.config);
        this.showToast('配置已保存', 'success');
      } catch (e) {
        this.showToast('保存失败: ' + e.message, 'error');
      } finally {
        this.saving = false;
      }
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
        this.showToast('保存失败: ' + e.message, 'error');
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
        const data = await api.get('/api/system/logs?lines=5000');
        this.systemLogs.allLogs = (data.logs || []).reverse();
        this.systemLogs.sources = data.sources || {};
        this.systemLogs.currentPage = 1;
        this.systemLogs.searchKeyword = '';
        this.systemLogs.selectedSource = '';
        this.applyLogFilter();
      } catch (e) {
        this.showToast('加载日志失败: ' + e.message, 'error');
      } finally {
        this.systemLogs.loading = false;
      }
    },

    applyLogFilter() {
      let logs = [...this.systemLogs.allLogs];
      if (this.systemLogs.selectedSource) {
        logs = logs.filter(l => l.program === this.systemLogs.selectedSource);
      }
      if (this.systemLogs.searchKeyword) {
        const kw = this.systemLogs.searchKeyword.toLowerCase();
        logs = logs.filter(l =>
          l.message.toLowerCase().includes(kw) ||
          l.program.toLowerCase().includes(kw) ||
          l.timestamp.includes(kw)
        );
      }
      this.systemLogs.filteredLogs = logs;
      this.systemLogs.currentPage = 1;
    },

    getLogTotalPages() {
      return Math.max(1, Math.ceil(this.systemLogs.filteredLogs.length / this.systemLogs.pageSize));
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
        const [whitelist, blacklist] = await Promise.all([
          api.get('/api/lists/whitelist'),
          api.get('/api/lists/blacklist')
        ]);
        this.listsData.whitelist = { ipv4: whitelist.allowed4 || {}, ipv6: whitelist.allowed6 || {} };
        this.listsData.blacklist = { ipv4: blacklist.blacklist4 || {}, ipv6: blacklist.blacklist6 || {} };
      } catch (e) {
        this.showToast('加载名单失败: ' + e.message, 'error');
      } finally {
        this.listsLoading = false;
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
        const rules = this.rp.rules.map(r => {
          const { _editIndex, ...clean } = r;
          return clean;
        });
        // Save rules one by one: existing rules use PUT, new rules use POST
        for (const rule of rules) {
          if (rule.id) {
            await api.put('/api/reverse-proxy/rules/' + rule.id, rule);
          } else {
            await api.post('/api/reverse-proxy/rules', rule);
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
        this.showToast('证书上传成功', 'success');
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
        this.showToast('删除失败: ' + e.message, 'error');
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
    const resp = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options });
    const json = await resp.json();
    if (json.success === false) throw new Error(json.message || '请求失败');
    const { success, message, ...data } = json;
    return data;
  },
  get(url) { return this.request(url); },
  post(url, body) { return this.request(url, { method: 'POST', body: JSON.stringify(body) }); },
  put(url, body) { return this.request(url, { method: 'PUT', body: JSON.stringify(body) }); },
  delete(url) { return this.request(url, { method: 'DELETE' }); }
};
