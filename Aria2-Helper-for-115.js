// ==UserScript==
// @name         115 网盘 Aria2 助手
// @version      0.2.2

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

// @require      https://cdn.bootcdn.net/ajax/libs/big-integer/1.6.51/BigInteger.min.js
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
// @version      0.2.2 @ 2022-10-03: 适配115新版接口加密方案。Credit to https://gist.github.com/showmethemoney2022/430ef0e45eeb7c99fedda2d2585cfe2e
// @inspiredBy   https://greasyfork.org/en/scripts/7749-115-download-helper
// @inspiredBy   https://github.com/robbielj/chrome-aria2-integration
// @inspiredBy   https://github.com/kkHAIKE/fake115
// @inspiredBy   https://github.com/QuChao/Watsilla
// @inspiredBy   https://gist.github.com/showmethemoney2022/430ef0e45eeb7c99fedda2d2585cfe2e
/* jshint -W097 */
'use strict';

// Configs
let Configs = {
    'debug_mode': true, // 是否开启调试模式
    "sync_clipboard": false, // 是否将下载链接同步到剪贴板，部分浏览器（如 Safari ）不支持
    'use_http': false, // 115 下载链接是否从 https 转换为 http （老版本 Aria2 需要）
    "rpc_path": 'http://你的域名:你的端口/jsonrpc', // RPC 地址
    "rpc_user": '', // RPC 用户名（若设置密码，请填写至 token 项）
    "rpc_token": '你的token', // RPC Token ，v1.18.4+ 支持，与用户名认证方式互斥
    "notification": true, // 是否开启推送通知
};


// Crypto
class MyRsa {
    constructor() {
        this.n = bigInt('8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683', 16)
        this.e = bigInt('10001', 16)
    };

    a2hex(byteArray) {
        var hexString = ''
        var nextHexByte
        for (var i = 0; i < byteArray.length; i++) {
            nextHexByte = byteArray[i].toString(16)
            if (nextHexByte.length < 2) {
                nextHexByte = '0' + nextHexByte
            }
            hexString += nextHexByte
        }
        return hexString
    }

    hex2a(hex) {
        var str = ''
        for (var i = 0; i < hex.length; i += 2) {
            str += String.fromCharCode(parseInt(hex.substr(i, 2), 16))
        }
        return str
    }

    pkcs1pad2(s, n) {
        if (n < s.length + 11) {
            return null
        }
        var ba = []
        var i = s.length - 1
        while (i >= 0 && n > 0) {
            ba[--n] = s.charCodeAt(i--)
        }
        ba[--n] = 0
        while (n > 2) { // random non-zero pad
            ba[--n] = 0xff
        }
        ba[--n] = 2
        ba[--n] = 0
        var c = this.a2hex(ba)
        return bigInt(c, 16)
    }

    pkcs1unpad2(a) {
        var b = a.toString(16)
        if (b.length % 2 !== 0) {
            b = '0' + b
        }
        var c = this.hex2a(b)
        var i = 1
        while (c.charCodeAt(i) !== 0) {
            i++
        }
        return c.slice(i + 1)
    }

    encrypt(text) {
        var m = this.pkcs1pad2(text, 0x80)
        var c = m.modPow(this.e, this.n)
        var h = c.toString(16)
        while (h.length < 0x80 * 2) {
            h = '0' + h
        }
        return h
    };

    decrypt(text) {
        var ba = []
        var i = 0
        while (i < text.length) {
            ba[i] = text.charCodeAt(i)
            i += 1
        }
        var a = bigInt(this.a2hex(ba), 16)
        var c = a.modPow(this.e, this.n)
        var d = this.pkcs1unpad2(c)
        return d
    };
}

class Crypto115 {
    constructor () {
      this.rsa = new MyRsa()

      this.kts = [240, 229, 105, 174, 191, 220, 191, 138, 26, 69, 232, 190, 125, 166, 115, 184, 222, 143, 231, 196, 69, 218, 134, 196, 155, 100, 139, 20, 106, 180, 241, 170, 56, 1, 53, 158, 38, 105, 44, 134, 0, 107, 79, 165, 54, 52, 98, 166, 42, 150, 104, 24, 242, 74, 253, 189, 107, 151, 143, 77, 143, 137, 19, 183, 108, 142, 147, 237, 14, 13, 72, 62, 215, 47, 136, 216, 254, 254, 126, 134, 80, 149, 79, 209, 235, 131, 38, 52, 219, 102, 123, 156, 126, 157, 122, 129, 50, 234, 182, 51, 222, 58, 169, 89, 52, 102, 59, 170, 186, 129, 96, 72, 185, 213, 129, 156, 248, 108, 132, 119, 255, 84, 120, 38, 95, 190, 232, 30, 54, 159, 52, 128, 92, 69, 44, 155, 118, 213, 27, 143, 204, 195, 184, 245]

      this.keyS = [0x29, 0x23, 0x21, 0x5E]

      this.keyL = [120, 6, 173, 76, 51, 134, 93, 24, 76, 1, 63, 70]
    }

    xor115Enc (src, srclen, key, keylen) {
      let i, j, k, mod4, ref, ref1, ref2, ret
      mod4 = srclen % 4
      ret = []
      if (mod4 !== 0) {
        for (i = j = 0, ref = mod4; (ref >= 0 ? j < ref : j > ref); i = ref >= 0 ? ++j : --j) {
          ret.push(src[i] ^ key[i % keylen])
        }
      }
      for (i = k = ref1 = mod4, ref2 = srclen; (ref1 <= ref2 ? k < ref2 : k > ref2); i = ref1 <= ref2 ? ++k : --k) {
        ret.push(src[i] ^ key[(i - mod4) % keylen])
      }
      return ret
    };

    getkey (length, key) {
      let i
      if (key != null) {
        return (() => {
          let j, ref, results
          results = []
          for (i = j = 0, ref = length; (ref >= 0 ? j < ref : j > ref); i = ref >= 0 ? ++j : --j) {
            results.push(((key[i] + this.kts[length * i]) & 0xff) ^ this.kts[length * (length - 1 - i)])
          }
          return results
        })()
      }
      if (length === 12) {
        return this.keyL.slice(0)
      }
      return this.keyS.slice(0)
    }

    asymEncode (src, srclen) {
      let i, j, m, ref, ret
      m = 128 - 11
      ret = ''
      for (i = j = 0, ref = Math.floor((srclen + m - 1) / m); (ref >= 0 ? j < ref : j > ref); i = ref >= 0 ? ++j : --j) {
        ret += this.rsa.encrypt(this.bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen))))
      }
      return window.btoa(this.rsa.hex2a(ret))
    }

    asymDecode (src, srclen) {
      let i, j, m, ref, ret
      m = 128
      ret = ''
      for (i = j = 0, ref = Math.floor((srclen + m - 1) / m); (ref >= 0 ? j < ref : j > ref); i = ref >= 0 ? ++j : --j) {
        ret += this.rsa.decrypt(this.bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen))))
      }
      return this.stringToBytes(ret)
    };

    symEncode (src, srclen, key1, key2) {
      let k1, k2, ret
      k1 = this.getkey(4, key1)
      k2 = this.getkey(12, key2)
      ret = this.xor115Enc(src, srclen, k1, 4)
      ret.reverse()
      ret = this.xor115Enc(ret, srclen, k2, 12)
      return ret
    };

    symDecode (src, srclen, key1, key2) {
      let k1, k2, ret
      k1 = this.getkey(4, key1)
      k2 = this.getkey(12, key2)
      ret = this.xor115Enc(src, srclen, k2, 12)
      ret.reverse()
      ret = this.xor115Enc(ret, srclen, k1, 4)
      return ret
    };

    bytesToString (buf) {
      let i, j, len, ret
      ret = ''
      for (j = 0, len = buf.length; j < len; j++) {
        i = buf[j]
        ret += String.fromCharCode(i)
      }
      return ret
    }

    stringToBytes (str) {
      let i, j, ref, ret
      ret = []
      for (i = j = 0, ref = str.length; (ref >= 0 ? j < ref : j > ref); i = ref >= 0 ? ++j : --j) {
        ret.push(str.charCodeAt(i))
      }
      return ret
    }

    m115_encode (str, timestamp) {
      const key = this.stringToBytes(md5(`!@###@#${timestamp}DFDR@#@#`))
      let temp = this.stringToBytes(str)
      temp = this.symEncode(temp, temp.length, key, null)
      temp = key.slice(0, 16).concat(temp)
      return {
        data: this.asymEncode(temp, temp.length),
        key
      }
    }

    m115_decode (str, key) {
      let temp = this.stringToBytes(window.atob(str))
      temp = this.asymDecode(temp, temp.length)
      return this.bytesToString(this.symDecode(temp.slice(16), temp.length - 16, key, temp.slice(0, 16)))
    }
}

//Crypto Instance
let crypto_115 = new Crypto115();

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
            resp_data = JSON.parse(crypto_115.m115_decode(resp.data, key))
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
                } = crypto_115.m115_encode(JSON.stringify({
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