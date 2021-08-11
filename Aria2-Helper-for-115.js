// ==UserScript==
// @name         115 网盘 Aria2 助手
// @version      0.2.1
// @description  直接将所选 115 下载链接发送至 Aria2
// @author       tces1
// @match        *://115.com/?ct=file*
// @encoding     utf-8
// @grant        GM_setClipboard
// @grant        GM_xmlhttpRequest
// @grant        GM_log
// @grant        GM_notification
// @grant        unsafeWindow
// @license      MIT
// @connect      *
// @require      https://raw.githubusercontent.com/tces1/Aria2-Helper-for-115/main/jsencrypt.js
// @require      https://cdn.bootcdn.net/ajax/libs/blueimp-md5/2.18.0/js/md5.min.js
// @run-at       document-end
// @namespace    https://greasyfork.org/users/373796
// ==/UserScript==
// @version      0.1.6 @ 2021-04-01: This project has not been maintained for nearly three years. I fixed it by the method in the fake115 project. If it involves infringement, please notify me tg @HadsFrank.
// @version      0.1.7 @ 2021-04-19: 很多人修改不好，在tg上问我，算了直接把代码复制过来，不用修改了.
// @version      0.1.8 @ 2021-04-20: 重新引入库.
// @version      0.1.9 @ 2021-05-14: 增加通知使能选项，且通知弹出后3秒自动消失.
// @version      0.2.0 @ 2021-05-17: 更改排队模型为并发，提高发送性能，并修改aria2按钮功能，调整为点击发送至Aria2，按住Ctrl(WIN)/Command(MAC)点击直接浏览器下载，按住Alt点击仅复制下载链接，鼠标悬停按钮可见提示
// @version      0.2.1 @ 2021-05-18: 支持目录下载，发送至aira2的请求将保留目录结构，浏览器直接下载不会保留目录结构按平铺下载，近期不会再开发新功能了，仅维护现有功能
// @inspiredBy   https://greasyfork.org/en/scripts/7749-115-download-helper
// @inspiredBy   https://github.com/robbielj/chrome-aria2-integration
// @inspiredBy   https://github.com/kkHAIKE/fake115
// @inspiredBy   https://github.com/QuChao/Watsilla
/* jshint -W097 */
'use strict';
 
// Configs
let Configs = {
    'debug_mode': true, // 是否开启调试模式
    "sync_clipboard": false, // 是否将下载链接同步到剪贴板，部分浏览器（如 Safari ）不支持
    'use_http': false, // 115 下载链接是否从 https 转换为 http （老版本 Aria2 需要）
    "rpc_path": 'http://localhost:6800/jsonrpc', // RPC 地址
    "rpc_user": '', // RPC 用户名（若设置密码，请填写至 token 项）
    "rpc_token": '', // RPC Token ，v1.18.4+ 支持，与用户名认证方式互斥
    "notification": true, // 是否开启推送通知
};
 
// Debug Func
let debug = Configs.debug_mode ? GM_log : function () {};
let emptyFunc = function () {};
 
let _notification = function (msg) {
    if (Configs.notification) {
        GM_notification({
            text: msg,
            timeout: 8000
        })
    }
}
 
// Aria2RPC
let GLOBAL_OPTION = {}
let Aria2RPC = (function ($win, $doc) {
    // privates
 
    // getGlobalOption
    function _getGlobalOption() {
        let rpcHeaders = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        };
 
        // auth method, pt.1
        if ('' !== Configs.rpc_user) {
            // user/password
            rpcHeaders['Authorization'] = 'Basic ' + $win.btoa(Configs.rpc_user + ':' + Configs.rpc_token);
        }
 
        return function (loadHandler, errorHandler) {
            // new task
            let reqParams = {
                'jsonrpc': '2.0',
                'method': 'aria2.getGlobalOption',
                'id': (+new Date()).toString(),
                'params': [],
            };
 
            // auth method, pt.2
            if ('' === Configs.rpc_user && '' !== Configs.rpc_token) {
                // secret, since v1.18.4
                reqParams.params.unshift('token:' + Configs.rpc_token);
            }
            debug(reqParams)
 
            // send to aria2, @todo: support metalink?
            GM_xmlhttpRequest({
                method: 'POST',
                url: Configs.rpc_path,
                headers: rpcHeaders,
                data: JSON.stringify(reqParams),
                onload: loadHandler || emptyFunc,
                onerror: errorHandler || emptyFunc
            });
        };
    }
 
    // send
    function _addTask() {
        let rpcHeaders = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        };
 
        // auth method, pt.1
        if ('' !== Configs.rpc_user) {
            // user/password
            rpcHeaders['Authorization'] = 'Basic ' + $win.btoa(Configs.rpc_user + ':' + Configs.rpc_token);
        }
 
        return function (link, options, loadHandler, errorHandler) {
            // new task
            let reqParams = {
                'jsonrpc': '2.0',
                'method': 'aria2.addUri',
                'id': (+new Date()).toString(),
                'params': [],
            };
 
            // auth method, pt.2
            if ('' === Configs.rpc_user && '' !== Configs.rpc_token) {
                // secret, since v1.18.4
                reqParams.params.unshift('token:' + Configs.rpc_token);
            }
 
            // download link
            if ('undefined' !== typeof link) {
                // @todo: multiple sources?
                reqParams.params.push([link]);
            } else {
                // link is required
                //errorHandler({});
                return;
            }
 
            // options
            if ('undefined' !== typeof options) {
                reqParams.params.push(options);
            }
            debug(reqParams)
            // send to aria2, @todo: support metalink?
            GM_xmlhttpRequest({
                method: 'POST',
                url: Configs.rpc_path,
                headers: rpcHeaders,
                data: JSON.stringify(reqParams),
                onload: loadHandler || emptyFunc,
                onerror: errorHandler || emptyFunc
            });
        };
    }
 
    return {
        // public
        add: _addTask(),
        getGlobalOption: _getGlobalOption(),
    };
})(unsafeWindow, unsafeWindow.document);
 
// Direct download
let DirectDownload = (function ($win, $doc) {
    // send
    function _addTask() {
        return function (link, loadHandler, errorHandler) {
            if ('undefined' !== typeof link) {
                const iframe = document.createElement("iframe");
                iframe.style.display = "none";
                iframe.style.height = 0;
                iframe.src = link;
                document.body.appendChild(iframe);
                setTimeout(() => {
                    iframe.remove();
                }, 5 * 1000);
                loadHandler.call()
            } else {
                // link is required
                //errorHandler({});
                return;
            }
        };
    }
    return {
        add: _addTask(),
    };
})(unsafeWindow, unsafeWindow.document);
 
 
let bytesToString, g_key_l, g_key_s, g_kts, m115_asym_decode, m115_asym_encode, m115_decode, m115_encode, m115_getkey, m115_sym_decode, m115_sym_encode, prsa, ref, srsa, stringToBytes, xor115_enc;
 
g_kts = [0xF0, 0xE5, 0x69, 0xAE, 0xBF, 0xDC, 0xBF, 0x5A, 0x1A, 0x45, 0xE8, 0xBE, 0x7D, 0xA6, 0x73, 0x88, 0xDE, 0x8F, 0xE7, 0xC4, 0x45, 0xDA, 0x86, 0x94, 0x9B, 0x69, 0x92, 0x0B, 0x6A, 0xB8, 0xF1, 0x7A, 0x38, 0x06, 0x3C, 0x95, 0x26, 0x6D, 0x2C, 0x56, 0x00, 0x70, 0x56, 0x9C, 0x36, 0x38, 0x62, 0x76, 0x2F, 0x9B, 0x5F, 0x0F, 0xF2, 0xFE, 0xFD, 0x2D, 0x70, 0x9C, 0x86, 0x44, 0x8F, 0x3D, 0x14, 0x27, 0x71, 0x93, 0x8A, 0xE4, 0x0E, 0xC1, 0x48, 0xAE, 0xDC, 0x34, 0x7F, 0xCF, 0xFE, 0xB2, 0x7F, 0xF6, 0x55, 0x9A, 0x46, 0xC8, 0xEB, 0x37, 0x77, 0xA4, 0xE0, 0x6B, 0x72, 0x93, 0x7E, 0x51, 0xCB, 0xF1, 0x37, 0xEF, 0xAD, 0x2A, 0xDE, 0xEE, 0xF9, 0xC9, 0x39, 0x6B, 0x32, 0xA1, 0xBA, 0x35, 0xB1, 0xB8, 0xBE, 0xDA, 0x78, 0x73, 0xF8, 0x20, 0xD5, 0x27, 0x04, 0x5A, 0x6F, 0xFD, 0x5E, 0x72, 0x39, 0xCF, 0x3B, 0x9C, 0x2B, 0x57, 0x5C, 0xF9, 0x7C, 0x4B, 0x7B, 0xD2, 0x12, 0x66, 0xCC, 0x77, 0x09, 0xA6];
 
g_key_s = [0x29, 0x23, 0x21, 0x5E];
 
g_key_l = [0x42, 0xDA, 0x13, 0xBA, 0x78, 0x76, 0x8D, 0x37, 0xE8, 0xEE, 0x04, 0x91];
 
m115_getkey = function (length, key) {
    let i;
    if (key != null) {
        return (function () {
            let j, ref, results;
            results = [];
            for (i = j = 0, ref = length;
                (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
                results.push(((key[i] + g_kts[length * i]) & 0xff) ^ g_kts[length * (length - 1 - i)]);
            }
            return results;
        })();
    }
    if (length === 12) {
        return g_key_l.slice(0);
    }
    return g_key_s.slice(0);
};
 
xor115_enc = function (src, srclen, key, keylen) {
    let i, j, k, mod4, ref, ref1, ref2, ret;
    mod4 = srclen % 4;
    ret = [];
    if (mod4 !== 0) {
        for (i = j = 0, ref = mod4;
            (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
            ret.push(src[i] ^ key[i % keylen]);
        }
    }
    for (i = k = ref1 = mod4, ref2 = srclen;
        (ref1 <= ref2 ? k < ref2 : k > ref2); i = ref1 <= ref2 ? ++k : --k) {
        ret.push(src[i] ^ key[(i - mod4) % keylen]);
    }
    return ret;
};
 
m115_sym_encode = function (src, srclen, key1, key2) {
    let k1, k2, ret;
    k1 = m115_getkey(4, key1);
    k2 = m115_getkey(12, key2);
    ret = xor115_enc(src, srclen, k1, 4);
    ret.reverse();
    ret = xor115_enc(ret, srclen, k2, 12);
    return ret;
};
 
m115_sym_decode = function (src, srclen, key1, key2) {
    let k1, k2, ret;
    k1 = m115_getkey(4, key1);
    k2 = m115_getkey(12, key2);
    ret = xor115_enc(src, srclen, k2, 12);
    ret.reverse();
    ret = xor115_enc(ret, srclen, k1, 4);
    return ret;
};
 
stringToBytes = function (s) {
    let i, j, ref, ret;
    ret = [];
    for (i = j = 0, ref = s.length;
        (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
        ret.push(s.charCodeAt(i));
    }
    return ret;
};
 
bytesToString = function (b) {
    let i, j, len, ret;
    ret = '';
    for (j = 0, len = b.length; j < len; j++) {
        i = b[j];
        ret += String.fromCharCode(i);
    }
    return ret;
};
 
prsa = new JSEncrypt();
 
prsa.setPublicKey(`-----BEGIN RSA PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR3rWmeYnRClwLBB0Rq0dlm8Mr
PmWpL5I23SzCFAoNpJX6Dn74dfb6y02YH15eO6XmeBHdc7ekEFJUIi+swganTokR
IVRRr/z16/3oh7ya22dcAqg191y+d6YDr4IGg/Q5587UKJMj35yQVXaeFXmLlFPo
kFiz4uPxhrB7BGqZbQIDAQAB
-----END RSA PUBLIC KEY-----`);
 
srsa = new JSEncrypt();
 
srsa.setPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCMgUJLwWb0kYdW6feyLvqgNHmwgeYYlocst8UckQ1+waTOKHFC
TVyRSb1eCKJZWaGa08mB5lEu/asruNo/HjFcKUvRF6n7nYzo5jO0li4IfGKdxso6
FJIUtAke8rA2PLOubH7nAjd/BV7TzZP2w0IlanZVS76n8gNDe75l8tonQQIDAQAB
AoGANwTasA2Awl5GT/t4WhbZX2iNClgjgRdYwWMI1aHbVfqADZZ6m0rt55qng63/
3NsjVByAuNQ2kB8XKxzMoZCyJNvnd78YuW3Zowqs6HgDUHk6T5CmRad0fvaVYi6t
viOkxtiPIuh4QrQ7NUhsLRtbH6d9s1KLCRDKhO23pGr9vtECQQDpjKYssF+kq9iy
A9WvXRjbY9+ca27YfarD9WVzWS2rFg8MsCbvCo9ebXcmju44QhCghQFIVXuebQ7Q
pydvqF0lAkEAmgLnib1XonYOxjVJM2jqy5zEGe6vzg8aSwKCYec14iiJKmEYcP4z
DSRms43hnQsp8M2ynjnsYCjyiegg+AZ87QJANuwwmAnSNDOFfjeQpPDLy6wtBeft
5VOIORUYiovKRZWmbGFwhn6BQL+VaafrNaezqUweBRi1PYiAF2l3yLZbUQJAf/nN
4Hz/pzYmzLlWnGugP5WCtnHKkJWoKZBqO2RfOBCq+hY4sxvn3BHVbXqGcXLnZPvo
YuaK7tTXxZSoYLEzeQJBAL8Mt3AkF1Gci5HOug6jT4s4Z+qDDrUXo9BlTwSWP90v
wlHF+mkTJpKd5Wacef0vV+xumqNorvLpIXWKwxNaoHM=
-----END RSA PRIVATE KEY-----`);
 
m115_asym_encode = function (src, srclen) {
    let i, j, m, ref, ret;
    m = 128 - 11;
    ret = '';
    for (i = j = 0, ref = Math.floor((srclen + m - 1) / m);
        (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
        ret += window.atob(prsa.encrypt(bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen)))));
    }
    return window.btoa(ret);
};
 
m115_asym_decode = function (src, srclen) {
    let i, j, m, ref, ret;
    m = 128;
    ret = '';
    for (i = j = 0, ref = Math.floor((srclen + m - 1) / m);
        (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
        ret += srsa.decrypt(window.btoa(bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen)))));
    }
    return stringToBytes(ret);
};
 
m115_encode = function (src, tm) {
    let key, tmp;
    key = stringToBytes(md5(`!@###@#${tm}DFDR@#@#`));
    tmp = stringToBytes(src);
    tmp = m115_sym_encode(tmp, tmp.length, key, null);
    tmp = key.slice(0, 16).concat(tmp);
    return {
        data: m115_asym_encode(tmp, tmp.length),
        key
    };
};
 
m115_decode = function (src, key) {
    let tmp;
    tmp = stringToBytes(window.atob(src));
    tmp = m115_asym_decode(tmp, tmp.length);
    return bytesToString(m115_sym_decode(tmp.slice(16), tmp.length - 16, key, tmp.slice(0, 16)));
};
 
 
// Queue Manager
let QueueManager = (function ($win, $doc) {
    // constants
    const STATUS_DIR_UNPARSE = 5;
    const STATUS_DIR_PARSED = 4;
    const STATUS_SENT_TO_DIRECT_DOWNLOAD = 3;
    const STATUS_SENT_TO_ARIA2 = 2;
    const STATUS_START = 1;
    const STATUS_UNSTART = 0;
    const STATUS_DOWNLOAD_FAILURE = -1;
    const STATUS_LINK_FETCH_FAILURE = -2;
    const STATUS_GET_SUB_DIR_FAILURE = -5;
    const STATUS_GET_SUB_FILE_FAILURE = -6;
 
    // constructor
    function Mgr(options) {
        // options
        this.options = Mgr.validateOptions(options);
 
        // err msgs
        this.errMsgs = [];
 
        // get selected ones
        let selectedNodes = $doc.getElementById('js_cantain_box').querySelectorAll('li.selected');
 
        // build the queue
        this.queue = Array.from(selectedNodes).map(function (node) {
            return {
                'name': node.getAttribute('title'),
                'code': node.getAttribute('pick_code'),
                'link': null,
                'dir': '',
                'cookie': null,
                'status': '1' === node.getAttribute('file_type') ? STATUS_UNSTART : STATUS_DIR_UNPARSE
            };
        }, this);
    }
 
    // static
    Mgr.defaultOptions = {
        'copyOnly': false,
        'directDownload': false
    };
    Mgr.validateOptions = function (options) {
        // validation
        for (let key in options) {
            // skip the inherit ones
            if (!options.hasOwnProperty(key)) {
                continue;
            }
            if (!(key in Mgr.defaultOptions)) {
                // check existence
                throw Error('Invalid option: ' + key);
            } else if (typeof options[key] !== typeof Mgr.defaultOptions[key]) {
                // check type
                throw Error('Invalid option type: ' + key);
            }
        }
 
        // merge the options
        return Object.assign({}, Mgr.defaultOptions, options);
    };
 
    // methods
    Mgr.prototype.errorHandler = function (errCode, idx, resp) {
        this.errMsgs.push('File #' + idx + ': ');
        this.errMsgs.push("\t" + 'File Info: ' + JSON.stringify(this.queue[idx]));
        this.errMsgs.push("\t" + 'HTTP Status: ' + resp.status + ' - ' + resp.statusText);
 
        let errMsg = 'Unknown';
        if ('responseText' in resp) {
            try {
                let err = JSON.parse(resp.responseText);
                errMsg = err.error.message;
            } catch (e) {
                errMsg = e;
            }
        } else if ('msg' in resp) {
            errMsg = resp.msg;
        }
 
        this.errMsgs.push("\t" + 'Err Msg:' + errMsg);
 
        // update the status
        this.queue[idx].status = errCode;
        this.next();
    };
    Mgr.prototype.aria2DownloadHandler = function (idx, resp) {
        if (200 === resp.status && 'responseText' in resp) {
            // update the status
            this.queue[idx].status = STATUS_SENT_TO_ARIA2;
            this.next();
        } else {
            // failed
            this.errorHandler.call(this, STATUS_DOWNLOAD_FAILURE, idx, resp);
        }
    };
    Mgr.prototype.directDownloadHandler = function (idx) {
        this.queue[idx].status = STATUS_SENT_TO_DIRECT_DOWNLOAD;
        this.next();
    };
    Mgr.prototype.download = function (idx) {
        if (this.options.copyOnly) {
            this.queue[idx].status = STATUS_SENT_TO_ARIA2;
            this.next();
        }
        // send to dirct download
        else if (this.options.directDownload) {
            debug("direct download: ", this.queue[idx].link)
            DirectDownload.add(this.queue[idx].link,
                this.directDownloadHandler.bind(this, idx),
                this.errorHandler.bind(this, STATUS_DOWNLOAD_FAILURE, idx)
            )
        }
        // send to aria2
        else {
            Aria2RPC.add(this.queue[idx].link, {
                    'referer': $doc.URL,
                    'header': ['Cookie: ' + this.queue[idx].cookie, 'User-Agent: ' + $win.navigator.userAgent],
                    'dir': GLOBAL_OPTION.dir + "/" + this.queue[idx].dir,
                },
                this.aria2DownloadHandler.bind(this, idx),
                this.errorHandler.bind(this, STATUS_DOWNLOAD_FAILURE, idx)
            );
        }
    };
 
    Mgr.prototype.getSubDirsHandler = function (idx, page, raw_resp) {
        let resp = JSON.parse(raw_resp.responseText);
        if (!resp.state) {
            this.errorHandler.call(this, STATUS_GET_SUB_DIR_FAILURE, idx, resp);
        } else {
            resp_data = resp.data
        }
        this.DIR_TREE.push(resp_data.root)
        for (let item of resp_data.list) {
            if (item.hasOwnProperty("pid")) {
                for (let _item of this.DIR_TREE) {
                    if (item.pid == _item.fid) {
                        item.fn = _item.fn + "/" + item.fn
                        break
                    }
                }
                this.DIR_TREE.push(item)
            }
        }
        if (resp_data.has_next_page) {
            this.getSubDirs(idx, page + 1)
        } else {
            debug("Directory tree:", this.DIR_TREE)
            this.getSubFiles(idx, 1)
        }
    };
 
 
    Mgr.prototype.getSubDirs = function (idx, page = 1) {
        request = (idx, page, onload, onerror) => {
            tmus = (new Date()).getTime();
            tm = Math.floor(tmus / 1000);
            GM_xmlhttpRequest({
                method: 'GET',
                url: `http://proapi.115.com/app/chrome/downfolders?pickcode=${this.queue[idx].code}&page=${page}&t=${tm}`,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': document.cookie,
                },
                onload,
                onerror,
            });
        }
        request(
            idx,
            page,
            this.getSubDirsHandler.bind(this, idx, page),
            this.errorHandler.bind(this, STATUS_GET_SUB_DIR_FAILURE, idx),
        )
    }
 
    Mgr.prototype.getSubFilesHandler = function (idx, page, raw_resp) {
        let resp = JSON.parse(raw_resp.responseText);
        if (!resp.state) {
            this.errorHandler.call(this, STATUS_GET_SUB_FILE_FAILURE, idx, resp);
        } else {
            resp_data = resp.data
        }
        for (let item of resp_data.list) {
            if (item.hasOwnProperty("pid")) {
                dir = ""
                for (let _item of this.DIR_TREE) {
                    if (item.pid == _item.fid) {
                        dir = _item.fn
                        break
                    }
                }
                this.queue.push({
                    name: 'generate_item',
                    code: item.pc,
                    link: null,
                    dir: dir,
                    cookie: null,
                    status: STATUS_UNSTART,
                })
            }
        }
        if (resp_data.has_next_page) {
            this.getSubFiles(idx, page + 1)
        } else {
            this.queue[idx].status = STATUS_DIR_PARSED;
            this.fetchLink(idx)
        }
    };
 
 
    Mgr.prototype.getSubFiles = function (idx, page = 1) {
        request = (idx, page, onload, onerror) => {
            tmus = (new Date()).getTime();
            tm = Math.floor(tmus / 1000);
            GM_xmlhttpRequest({
                method: 'GET',
                url: `http://proapi.115.com/app/chrome/downfiles?pickcode=${this.queue[idx].code}&page=${page}&t=${tm}`,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': document.cookie,
                },
                onload,
                onerror,
            });
        }
        request(
            idx,
            page,
            this.getSubFilesHandler.bind(this, idx, page),
            this.errorHandler.bind(this, STATUS_GET_SUB_FILE_FAILURE, idx),
        )
    }
 
 
    Mgr.prototype.fetchLinkHandler = function (idx, key, raw_resp) {
        let resp = JSON.parse(raw_resp.responseText);
        if (!resp.state) {
            alert(resp.msg);
            this.errorHandler.call(this, STATUS_LINK_FETCH_FAILURE, idx, resp);
        } else {
            resp_data = JSON.parse(m115_decode(resp.data, key))
        }
 
        final_cookie = document.cookie
        resp = {}
        for (let i in resp_data) {
            resp = resp_data[i];
            break;
        }
 
        if ('url' in resp && 'url' in resp.url) {
            // update the link
            this.queue[idx].link = Configs.use_http ?
                resp.url.url.replace('https://', 'http://') // http only?
                :
                resp.url.url;
            this.queue[idx].cookie = final_cookie;
            this.queue[idx].status = STATUS_START;
            this.download(idx);
        } else {
            this.errorHandler.call(this, STATUS_LINK_FETCH_FAILURE, idx, resp);
        }
    };
 
 
    Mgr.prototype.fetchLink = function (idex_o = 0) {
        for (let idx = idex_o; idx < this.queue.length; idx++) {
            if (this.queue[idx].status === STATUS_UNSTART) {
                let data, key, tm, tmus;
                tmus = (new Date()).getTime();
                tm = Math.floor(tmus / 1000);
                ({
                    data,
                    key
                } = m115_encode(JSON.stringify({
                    pickcode: this.queue[idx].code
                }), tm));
                GM_xmlhttpRequest({
                    method: 'POST',
                    url: `http://proapi.115.com/app/chrome/downurl?t=${tm}`,
                    data: `data=${encodeURIComponent(data)}`,
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    onload: this.fetchLinkHandler.bind(this, idx, key),
                    onerror: this.errorHandler.bind(this, STATUS_LINK_FETCH_FAILURE, idx)
                });
            } else if (this.queue[idx].status === STATUS_DIR_UNPARSE) {
                this.getSubDirs(idx)
                break
            }
        }
    };
 
    Mgr.prototype.init = function () {
        // fetch link in parallel
        debug("Init queue:", this.queue)
        this.DIR_TREE = []
        this.FILE_TREE = []
        this.fetchLink();
    }
 
    Mgr.prototype.next = function () {
        // check if it's the queue is empty
        let nextIdx = this.queue.findIndex(function (file) {
            return STATUS_UNSTART === file.status;
        });
        // handle the next file
        if (-1 === nextIdx) {
            let report = this.queue.reduce(function (accumulator, file) {
                switch (file.status) {
                    // task finished
                    case STATUS_SENT_TO_DIRECT_DOWNLOAD:
                        accumulator.finished += 1;
                        accumulator.links.push(file.link);
                        break;
                    case STATUS_SENT_TO_ARIA2:
                        accumulator.finished += 1;
                        accumulator.links.push(file.link);
                        break;
                    case STATUS_DOWNLOAD_FAILURE:
                        accumulator.links.push(file.link);
                        break;
                    case STATUS_DIR_PARSED:
                        accumulator.dir += 1;
                        break;
                }
 
                return accumulator;
            }, {
                'links': [],
                'finished': 0,
                'dir': 0
            });
            let queueSize = this.queue.length - report.dir;
            let msg = [];
 
            msg.push('所选 ' + queueSize + ' 项已处理完毕：');
            if (!this.options.copyOnly) {
                if (report.finished == 0) {
                    msg.push('全部 发送失败');
                } else {
                    msg.push((queueSize === report.finished ? '全部' : '' + report.finished + '/' + queueSize) + ' 发送成功');
                }
            }
            _notification(msg.join("\n"));
            msg = [];
            if (this.options.copyOnly || Configs.sync_clipboard) {
                let downloadLinks = report.links.join("\n");
                if (false === /\sSafari\/\d+\.\d+\.\d+/.test($win.navigator.userAgent)) {
                    // sync to clipboard
                    GM_setClipboard(downloadLinks, 'text');
                    msg.push('下载地址已同步至剪贴板');
                    _notification(msg.join("\n"));
                } else if (this.options.copyOnly) {
                    prompt('本浏览器不支持访问剪贴板，请手动全选复制', downloadLinks);
                }
            }
 
            if (this.errMsgs.length) {
                throw Error(this.errMsgs.join("\n"));
            }
        }
    };
 
    return Mgr;
})(unsafeWindow, unsafeWindow.document);
 
// UI Helper
let UiHelper = (function ($win, $doc) {
    // privates
    let _triggerId = 'aria2Trigger';
 
    function _clickHandler(evt) {
 
        (new QueueManager({
            'directDownload': (evt.ctrlKey || evt.metaKey) && !evt.altKey,
            'copyOnly': evt.altKey && !evt.ctrlKey && !evt.metaKey,
        })).init();
        console.log("evt: ", evt)
        console.log('directDownload', (evt.ctrlKey || evt.metaKey) && !evt.altKey)
        console.log('copyOnly', evt.altKey && !evt.ctrlKey && !evt.metaKey)
 
        // kill the listener
        evt.target.removeEventListener('click', _clickHandler, false);
    }
 
    function _recordHandler(record) {
        // place the trigger
        let ariaTrigger = $doc.createElement('li');
        ariaTrigger.id = _triggerId;
        ariaTrigger.title = '点击发送至Aria2, 按住Ctrl(WIN)/Command(MAC)点击直接浏览器下载, 按住Alt点击仅复制下载链接';
        ariaTrigger.innerHTML = '<i class="icon-operate ifo-share"></i><span>Aria2</span>';
        // record.target.firstChild.appendChild(ariaTrigger);
        record.target.firstChild.insertBefore(ariaTrigger, record.target.firstChild.firstChild);
        record.target.childNodes[1].setAttribute("style", "display:none;")
        // make it clickable
        ariaTrigger.addEventListener('click', _clickHandler, false);
 
        // stop the observation
        //_observer.disconnect();
 
        return true;
    }
 
    // initialization
    function _init() {
        let container = $doc.getElementById('js_operate_box');
 
        // create a observer on the container
        new MutationObserver(function (records) {
            records.filter(function () {
                return null === $doc.getElementById(_triggerId);
            }).some(_recordHandler);
        }).observe(container, {
            'childList': true,
        });
        Aria2RPC.getGlobalOption(
            function (resp) {
                if (200 === resp.status && 'responseText' in resp) {
                    // update the status
                    GLOBAL_OPTION = JSON.parse(resp.responseText)["result"]
                    debug(GLOBAL_OPTION)
                }
            },
            undefined
        )
    }
 
    return {
        // public
        init: _init
    };
})(unsafeWindow, unsafeWindow.document);
 
// fire
UiHelper.init();
