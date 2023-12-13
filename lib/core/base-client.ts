import {EventEmitter} from "events"
import {createHash, randomBytes} from "crypto"
import {Readable} from "stream"
import Network from "./network"
import axios from "axios"
import Ecdh from "./ecdh"
import Writer from "./writer"
import * as tlv from "./tlv"
import * as tea from "./tea"
import * as pb from "./protobuf"
import * as jce from "./jce"
import {BUF0, BUF4, BUF16, NOOP, md5, timestamp, lock, hide, unzip, int32ip2str} from "./constants"
import {ShortDevice, Device, generateFullDevice, Platform, Apk, getApkInfo} from "./device"
import {Version} from "../client";

const FN_NEXT_SEQ = Symbol("FN_NEXT_SEQ")
const FN_SEND = Symbol("FN_SEND")
const FN_SEND_LOGIN = Symbol("FN_SEND_LOGIN")
const HANDLERS = Symbol("HANDLERS")
const NET = Symbol("NET")
const ECDH = Symbol("ECDH")
const IS_ONLINE = Symbol("IS_ONLINE")
const LOGIN_LOCK = Symbol("LOGIN_LOCK")
const HEARTBEAT = Symbol("HEARTBEAT")

export enum VerboseLevel {
	Fatal, Mark, Error, Warn, Info, Debug, Trace
}

export class ApiRejection {
	constructor(public code: number, public message = "unknown") {
		this.code = Number(this.code)
		this.message = this.message?.toString() || "unknown"
	}
}

type Packet = {
	cmd: string
	type: number
	callbackId?: number
	body: Buffer
}

export enum QrcodeResult {
	OtherError = 0,
	Timeout = 0x11,
	WaitingForScan = 0x30,
	WaitingForConfirm = 0x35,
	Canceled = 0x36,
}

export interface BaseClient {
	/** 收到二维码 */
	on(name: "internal.qrcode", listener: (this: this, qrcode: Buffer) => void): this

	/** 收到滑动验证码 */
	on(name: "internal.slider", listener: (this: this, url: string) => void): this

	/** 登录保护验证 */
	on(name: "internal.verify", listener: (this: this, url: string, phone: string) => void): this

	/** token过期(此时已掉线) */
	on(name: "internal.error.token", listener: (this: this) => void): this

	/** 网络错误 */
	on(name: "internal.error.network", listener: (this: this, code: number, message: string) => void): this

	/** 密码登录相关错误 */
	on(name: "internal.error.login", listener: (this: this, code: number, message: string) => void): this

	/** 扫码登录相关错误 */
	on(name: "internal.error.qrcode", listener: (this: this, code: QrcodeResult, message: string) => void): this

	/** 登录成功 */
	on(name: "internal.online", listener: (this: this, token: Buffer, nickname: string, gender: number, age: number) => void): this

	/** token更新 */
	on(name: "internal.token", listener: (this: this, token: Buffer) => void): this

	/** 服务器强制下线 */
	on(name: "internal.kickoff", listener: (this: this, reason: string) => void): this

	/** 业务包 */
	on(name: "internal.sso", listener: (this: this, cmd: string, payload: Buffer, seq: number) => void): this

	/** 日志信息 */
	on(name: "internal.verbose", listener: (this: this, verbose: unknown, level: VerboseLevel) => void): this

	on(name: string | symbol, listener: (this: this, ...args: any[]) => void): this
}

export class BaseClient extends EventEmitter {

	private [IS_ONLINE] = false
	private [LOGIN_LOCK] = false
	private [ECDH] = new Ecdh
	private readonly [NET] = new Network
	// 回包的回调函数
	private readonly [HANDLERS] = new Map<number, (buf: Buffer) => void>()

	readonly apk: Apk
	readonly device: Device
	readonly sig = {
		seq: randomBytes(4).readUInt32BE() & 0xfff,
		session: randomBytes(4),
		randkey: randomBytes(16),
		tgtgt: randomBytes(16),
		tgt: BUF0,
		skey: BUF0,
		ksid: BUF0,
		d2: BUF0,
		d2key: BUF0,
		t104: BUF0,
		t174: BUF0,
		t546: BUF0,
		t547: BUF0,
		t553: BUF0,
		qrsig: BUF0,
		/** 大数据上传通道 */
		bigdata: {
			ip: "",
			port: 0,
			sig_session: BUF0,
			session_key: BUF0,
		},
		/** 心跳包 */
		hb480: (() => {
			const buf = Buffer.alloc(9)
			buf.writeUInt32BE(this.uin)
			buf.writeInt32BE(0x19e39, 5)
			return pb.encode({
				1: 1152,
				2: 9,
				4: buf
			})
		})(),
		/** 上次cookie刷新时间 */
		emp_time: 0,
		time_diff: 0,
		requestTokenTime: 0,
		sign_addr: ""
	}
	readonly pskey: { [domain: string]: Buffer } = {}
	/** 心跳间隔(秒) */
	protected interval = 30
	/** 随心跳一起触发的函数，可以随意设定 */
	protected heartbeat = NOOP
	// 心跳定时器
	private [HEARTBEAT]!: NodeJS.Timeout
	private ssoPacketList: Packet[] = [];
	/** 数据统计 */
	protected readonly statistics = {
		start_time: timestamp(),
		lost_times: 0,
		recv_pkt_cnt: 0,
		sent_pkt_cnt: 0,
		lost_pkt_cnt: 0,
		recv_msg_cnt: 0,
		sent_msg_cnt: 0,
		msg_cnt_per_min: 0,
		remote_ip: "",
		remote_port: 0,
	}
	protected signCmd = [
		'wtlogin.login',
		'wtlogin.exchange_emp',
		'MessageSvc.PbSendMsg',
		'trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey',
		'trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Establish',
		'trpc.o3.ecdh_access.EcdhAccess.SsoSecureA2Access'
	];

	constructor(public readonly uin: number, p: Platform = Platform.Android, v: Version = "8.9.63", d?: ShortDevice) {
		super()
		this.apk = getApkInfo(p, v)
		this.device = generateFullDevice(d || uin)
		this.sig.ksid = Buffer.from(`|${this.device.imei}|${this.apk.name}`)
		this[NET].on("error", err => this.emit("internal.verbose", err.message, VerboseLevel.Error))
		this[NET].on("close", () => {
			this.statistics.remote_ip = ""
			this.statistics.remote_port = 0
			this[NET].remoteAddress && this.emit("internal.verbose", `${this[NET].remoteAddress}:${this[NET].remotePort} closed`, VerboseLevel.Mark)
		})
		this[NET].on("connect2", () => {
			this.statistics.remote_ip = this[NET].remoteAddress as string
			this.statistics.remote_port = this[NET].remotePort as number
			this.emit("internal.verbose", `${this[NET].remoteAddress}:${this[NET].remotePort} connected`, VerboseLevel.Mark)
			syncTimeDiff.call(this).then()
		})
		this[NET].on("packet", packetListener.bind(this))
		this[NET].on("lost", lostListener.bind(this))
		this.on("internal.online", onlineListener)
		this.on("internal.sso", ssoListener)
		lock(this, "uin")
		lock(this, "apk")
		lock(this, "device")
		lock(this, "sig")
		lock(this, "pskey")
		lock(this, "statistics")
		hide(this, "heartbeat")
		hide(this, "interval")
	}

	/** 设置连接服务器，不设置则自动搜索 */
	setRemoteServer(host?: string, port?: number) {
		if (host && port) {
			this[NET].host = host
			this[NET].port = port
			this[NET].auto_search = false
		} else {
			this[NET].auto_search = true
		}
	}

	setSignAddr(addr?: string) {
		if (!addr) return
		if (!addr.startsWith("http") && !addr.startsWith("https")) {
			this.sig.sign_addr = "http://" + addr
		}
		this.sig.sign_addr = addr
	}

	/** 是否为在线状态 (可以收发业务包的状态) */
	isOnline() {
		return this[IS_ONLINE]
	}

	/** 下线 (keepalive: 是否保持tcp连接) */
	async logout(keepalive = false) {
		await register.call(this, true)
		if (!keepalive && this[NET].connected) {
			this.terminate()
			await new Promise(resolve => this[NET].once("close", resolve))
		}
	}

	/** 关闭连接 */
	terminate() {
		this[IS_ONLINE] = false
		this[NET].destroy()
	}

	/** 使用接收到的token登录 */
	async tokenLogin(token: Buffer = BUF0) {
		if (![144, 152, 160, 0].includes(token.length))
			throw new Error("bad token")
		if (token.length) {
			this.sig.session = randomBytes(4)
			this.sig.randkey = randomBytes(16)
			this[ECDH] = new Ecdh
			this.sig.d2key = token.slice(0, 16)
			if (token.length === 160) {
				this.sig.d2 = token.slice(16, token.length - 80)
				this.sig.tgt = token.slice(token.length - 80)
			} else {
				this.sig.d2 = token.slice(16, token.length - 72)
				this.sig.tgt = token.slice(token.length - 72)
			}
			this.sig.tgtgt = md5(this.sig.d2key)
		}
		const t = tlv.getPacker(this);
		const tlvs = [
			t(0x8),
			t(0x18),
			t(0x100),
			t(0x108),
			t(0x10a),
			t(0x112),
			t(0x116),
			t(0x141),
			t(0x142),
			t(0x143),
			t(0x144),
			t(0x145),
			t(0x147),
			t(0x154),
			t(0x177),
			t(0x187),
			t(0x188),
			t(0x511)
		];
		if (this.apk.ssover >= 5) {
			tlvs.push(t(0x544, -1, await this.getT544("810_a")));
			if (this.sig.t553) tlvs.push(t(0x553));
		}
		if (this.device.qImei16) tlvs.push(t(0x545, this.device.qImei16))
		else {
			tlvs.push(t(0x194));
			tlvs.push(t(0x202));
		}
		let writer = new Writer()
			.writeU16(11)
			.writeU16(tlvs.length);
		for (let tlv of tlvs) writer.writeBytes(tlv);
		const body = writer.read();
		if (token != BUF0) {
			this[FN_SEND_LOGIN]("wtlogin.exchange_emp", body);
			return BUF0;
		}
		return body;
	}

	/** T544接口 */
	async getT544(cmd: string): Promise<Buffer> {
		let sign = BUF0;
		if (this.sig.sign_addr && this.apk.qua) {
			const time = Date.now();
			let qImei36 = this.device.qImei36 || this.device.qImei16;
			let post_params = {
				ver: this.apk.ver,
				uin: this.uin || 0,
				data: cmd,
				android_id: this.device.android_id,
				qimei36: qImei36 || this.device.android_id,
				guid: this.device.guid.toString('hex'),
				version: this.apk.sdkver
			};
			let url = new URL(this.sig.sign_addr);
			let path = url.pathname;
			if (path.substring(path.length - 1) === '/') {
				path += 'energy';
			} else {
				path = path.replace(/\/sign$/, '/energy');
			}
			url.pathname = path;
			const data = await get.bind(this)(url.href, post_params);
			this.emit("internal.verbose", `getT544 ${cmd} result(${Date.now() - time}ms): ${JSON.stringify(data)}`, VerboseLevel.Debug);
			if (data.code === 0) {
				if (typeof (data.data) === 'string') {
					sign = Buffer.from(data.data, 'hex');
				} else if (typeof (data.data?.sign) === 'string') {
					sign = Buffer.from(data.data.sign, 'hex');
				}
			} else {
				if (data.code === 1) {
					if (data.msg.includes('Uin is not registered.')) {
						if (await this.apiRegister.call(this)) {
							return await this.getT544(cmd);
						}
					}
				}
				this.emit("internal.verbose", `签名api(energy)异常： ${cmd} result(${Date.now() - time}ms): ${JSON.stringify(data)}`, VerboseLevel.Error);
			}
		}
		return sign;
	}

	/** 签名接口 */
	async getSign(cmd: string, seq: number, body: Buffer): Promise<Buffer> {
		let params = BUF0;
		if (!this.sig.sign_addr) {
			return params;
		}
		let qImei36 = this.device.qImei36 || this.device.qImei16;
		if (this.apk.qua) {
			const time = Date.now();
			let post_params = {
				qua: this.apk.qua,
				uin: this.uin || 0,
				cmd: cmd,
				seq: seq,
				android_id: this.device.android_id,
				qimei36: qImei36 || this.device.android_id,
				buffer: body.toString('hex'),
				guid: this.device.guid.toString('hex'),
			};
			let url = new URL(this.sig.sign_addr);
			let path = url.pathname;
			if (path.substring(path.length - 1) === '/') {
				path += 'sign';
			}
			url.pathname = path;
			const data = await get.bind(this)(url.href, post_params, true);
			this.emit("internal.verbose", `getSign ${cmd} result(${Date.now() - time}ms): ${JSON.stringify(data)}`, VerboseLevel.Debug);
			if (data.code === 0) {
				const Data = data.data || {};
				params = this.generateSignPacket(Data.sign, Data.token, Data.extra);
				let list = Data.ssoPacketList || Data.requestCallback || [];
				if (list.length < 1 && cmd.includes('wtlogin')) {
					this.requestToken().then();
				} else {
					this.ssoPacketListHandler(list).then();
				}
			} else {
				if (data.code === 1) {
					if (data.msg.includes('Uin is not registered.')) {
						if (await this.apiRegister.call(this)) {
							return await this.getSign(cmd, seq, body);
						}
					}
				}
				this.emit("internal.verbose", `签名api异常： ${cmd} result(${Date.now() - time}ms): ${JSON.stringify(data)}`, VerboseLevel.Error);
			}
		}
		return params;
	}

	/** 签名接口注册 */
	async apiRegister() {
		let qImei36 = this.device.qImei36 || this.device.qImei16;
		const time = Date.now();
		let post_params = {
			uin: this.uin || 0,
			android_id: this.device.android_id,
			qimei36: qImei36,
			guid: this.device.guid.toString('hex')
		};
		let url = new URL(this.sig.sign_addr);
		let path = url.pathname;
		if (path.substring(path.length - 1) === '/') {
			path += 'register';
		} else {
			path = path.replace(/\/sign$/, '/register');
		}
		url.pathname = path;
		const data = await get.bind(this)(url.href, post_params);
		this.emit("internal.verbose", `register result(${Date.now() - time}ms): ${JSON.stringify(data)}`, VerboseLevel.Debug);
		if (data.code == 0) {
			return true;
		}
		;
		this.emit("internal.verbose", `签名api注册异常：result(${Date.now() - time}ms): ${JSON.stringify(data)}`, VerboseLevel.Error);
		return false;
	}

	generateSignPacket(sign: String, token: String, extra: String) {
		let pb_data = {
			1: Buffer.from(sign, 'hex'),
			2: Buffer.from(token, 'hex'),
			3: Buffer.from(extra, 'hex')
		}
		return Buffer.from(pb.encode(pb_data));
	}

	buildReserveFields(cmd: string, sec_info: any) {
		let qImei36 = this.device.qImei36 || this.device.qImei16;
		let reserveFields;
		if (this.apk.ssover >= 20 && false) {
			reserveFields = {
				9: 1,
				11: 2052,
				12: qImei36,
				14: 0,
				15: '',
				16: this.uin || '',
				18: 0,
				19: 1,
				20: 1,
				21: 32,
				24: sec_info,
				26: 100,
				28: 3
			};
		} else {
			reserveFields = {
				9: 1,
				12: qImei36,
				14: 0,
				16: this.uin,
				18: 0,
				19: 1,
				20: 1,
				21: 0,
				24: sec_info,
				28: 3
			};
		}
		return Buffer.from(pb.encode(reserveFields));
	}

	async requestToken() {
		if ((Date.now() - this.sig.requestTokenTime) >= (60 * 60 * 1000)) {
			this.sig.requestTokenTime = Date.now();
			let list = await this.requestSignToken();
			await this.ssoPacketListHandler(list);
		}
	}

	async requestSignToken(): Promise<[]> {
		if (!this.sig.sign_addr) {
			return [];
		}
		let qImei36 = this.device.qImei36 || this.device.qImei16;
		if (this.apk.qua) {
			const time = Date.now();
			let post_params = {
				uin: this.uin || 0,
				android_id: this.device.android_id,
				qimei36: qImei36 || this.device.android_id,
				guid: this.device.guid.toString('hex'),
			};
			let url = new URL(this.sig.sign_addr);
			let path = url.pathname;
			if (path.substring(path.length - 1) === '/') {
				path += 'request_token';
			} else {
				path = path.replace(/\/sign$/, '/request_token');
			}
			url.pathname = path;
			const data = await get.bind(this)(url.href, post_params);
			this.emit("internal.verbose", `requestSignToken result(${Date.now() - time}ms): ${JSON.stringify(data)}`, VerboseLevel.Debug);
			if (data.code === 0) {
				let ssoPacketList = data.data?.ssoPacketList || data.data?.requestCallback || data.data;
				if (!ssoPacketList || ssoPacketList.length < 1) return [];
				return ssoPacketList;
			} else if (data.code === 1) {
				if (data.msg.includes('Uin is not registered.')) {
					if (await this.apiRegister.call(this)) {
						return await this.requestSignToken();
					}
				}
			}
		}
		return [];
	}

	async ssoPacketListHandler(list: any) {
		let handle = (list: any) => {
			let new_list: Packet[] = [];
			for (let val of list) {
				try {
					let data = pb.decode(Buffer.from(val.body, 'hex'));
					val.type = data[1].toString();
				} catch (err) {
				}
				new_list.push(val);
			}
			return new_list;
		};
		if (list === null && this.isOnline()) {
			if (this.ssoPacketList.length > 0) {
				list = this.ssoPacketList;
				this.ssoPacketList = [];
			}
		}
		if (!list || !list.length) return;
		if (!this.isOnline()) {
			list = handle(list);
			if (this.ssoPacketList.length > 0) {
				let list1 = this.ssoPacketList;
				this.ssoPacketList = [];
				for (let val of list) {
					let ssoPacket: any = list1.find((data: any) => {
						return data.cmd === val.cmd && data.type === val.type;
					});
					if (ssoPacket) {
						ssoPacket.body = val.body;
					} else {
						list1.push(val);
					}
				}
			} else {
				this.ssoPacketList = this.ssoPacketList.concat(list);
			}
			return;
		}

		for (let ssoPacket of list) {
			let cmd = ssoPacket.cmd;
			let body = Buffer.from(ssoPacket.body as unknown as string, 'hex');
			let callbackId = ssoPacket.callbackId as number;
			let payload = await this.sendUni(cmd, body);
			this.emit("internal.verbose", `sendUni ${cmd} result: ${payload.toString('hex')}`, VerboseLevel.Debug);
			if (callbackId > -1) {
				await this.submitSsoPacket(cmd, callbackId, payload);
			}
		}
	}

	async submitSsoPacket(cmd: string, callbackId: number, body: Buffer) {
		if (!this.sig.sign_addr) {
			return [];
		}
		let qImei36 = this.device.qImei36 || this.device.qImei16;
		if (this.apk.qua) {
			const time = Date.now();
			let post_params = {
				ver: this.apk.ver,
				qua: this.apk.qua,
				uin: this.uin || 0,
				cmd: cmd,
				callback_id: callbackId,
				android_id: this.device.android_id,
				qimei36: qImei36 || this.device.android_id,
				buffer: body.toString('hex'),
				guid: this.device.guid.toString('hex'),
			};
			let url = new URL(this.sig.sign_addr);
			let path = url.pathname;
			if (path.substring(path.length - 1) === '/') {
				path += 'submit';
			} else {
				path = path.replace(/\/sign$/, '/submit');
			}
			url.pathname = path;
			const data = await get.bind(this)(url.href, post_params);
			this.emit("internal.verbose", `submitSsoPacket result(${Date.now() - time}ms): ${JSON.stringify(data)}`, VerboseLevel.Debug);
			if (data.code === 0) {
				let ssoPacketList = data.data?.ssoPacketList || data.data?.requestCallback || data.data;
				if (!ssoPacketList || ssoPacketList.length < 1) return [];
				return ssoPacketList;
			}
		}
		return [];
	}

	/**
	 * 使用密码登录
	 * @param md5pass 密码的md5值
	 */
	async passwordLogin(md5pass: Buffer) {
		this.sig.session = randomBytes(4)
		this.sig.randkey = randomBytes(16)
		this.sig.tgtgt = randomBytes(16)
		this[ECDH] = new Ecdh
		const t = tlv.getPacker(this)
		const tlvs = [
			t(0x1),
			t(0x8),
			t(0x18),
			t(0x100),
			t(0x106, md5pass),
			t(0x107),
			t(0x116),
			t(0x141),
			t(0x142),
			t(0x144),
			t(0x145),
			t(0x147),
			t(0x154),
			t(0x177),
			t(0x187),
			t(0x188),
			t(0x191),
			t(0x511),
			t(0x516),
			t(0x521, 0),
			t(0x525),
			t(0x542),
			t(0x548)
		]
		if (this.apk.ssover >= 12) {
			tlvs.push(t(0x544, -1, await this.getT544("810_9")))
			if (this.sig.t553) tlvs.push(t(0x553))
		}
		if (this.device.qImei16) tlvs.push(t(0x545, this.device.qImei16))
		else {
			tlvs.push(t(0x194))
			tlvs.push(t(0x202))
		}
		let writer = new Writer()
			.writeU16(9)
			.writeU16(tlvs.length)
		for (let tlv of tlvs) writer.writeBytes(tlv)
		this[FN_SEND_LOGIN]("wtlogin.login", writer.read())
	}

	/** 收到滑动验证码后，用于提交滑动验证码 */
	async submitSlider(ticket: string) {
		try {
			if (this.sig.t546.length) this.sig.t547 = this.calcPoW(this.sig.t546)
		} catch {
		}
		ticket = String(ticket).trim()
		const t = tlv.getPacker(this)
		const tlvs = [
			t(0x8),
			t(0x104),
			t(0x116),
			t(0x193, ticket),
		]
		if (this.apk.ssover >= 12) {
			tlvs.push(t(0x544, -1, await this.getT544("810_2")))
			if (this.sig.t553) tlvs.push(t(0x553))
		}
		if (this.sig.t547.length) tlvs.push(t(0x547))
		let writer = new Writer()
			.writeU16(2)
			.writeU16(tlvs.length)
		for (let tlv of tlvs) writer.writeBytes(tlv)
		this[FN_SEND_LOGIN]("wtlogin.login", writer.read())
	}

	/** 收到设备锁验证请求后，用于发短信 */
	sendSmsCode() {
		const t = tlv.getPacker(this)
		const body = new Writer()
			.writeU16(8)
			.writeU16(6)
			.writeBytes(t(0x8))
			.writeBytes(t(0x104))
			.writeBytes(t(0x116))
			.writeBytes(t(0x174))
			.writeBytes(t(0x17a))
			.writeBytes(t(0x197))
			.read()
		this[FN_SEND_LOGIN]("wtlogin.login", body)
	}

	/** 提交短信验证码 */
	async submitSmsCode(code: string) {
		code = String(code).trim()
		if (Buffer.byteLength(code) !== 6)
			code = "123456"
		const t = tlv.getPacker(this)
		const tlvs = [
			t(0x8),
			t(0x104),
			t(0x116),
			t(0x174),
			t(0x17c, code),
			t(0x198),
			t(0x401)
		]
		if (this.apk.ssover >= 12) {
			tlvs.push(t(0x544, -1, await this.getT544("810_7")))
			if (this.sig.t553) tlvs.push(t(0x553))
		}
		if (this.sig.t547.length) tlvs.push(t(0x547))
		let writer = new Writer()
			.writeU16(7)
			.writeU16(tlvs.length)
		for (let tlv of tlvs) writer.writeBytes(tlv)
		this[FN_SEND_LOGIN]("wtlogin.login", writer.read())
	}

	/** 获取登录二维码(模拟手表协议扫码登录) */
	async fetchQrcode() {
		const t = tlv.getPacker(this)
		const body = new Writer()
			.writeU16(0)
			.writeU32(16)
			.writeU64(0)
			.writeU8(8)
			.writeTlv(BUF0)
			.writeU16(6)
			.writeBytes(t(0x16))
			.writeBytes(t(0x1B))
			.writeBytes(t(0x1D))
			.writeBytes(t(0x1F))
			.writeBytes(t(0x33))
			.writeBytes(t(0x35))
			.read()
		const {pkt, seq} = await buildCode2dPacket.call(this, 0x31, 0x11100, body)
		this[FN_SEND](pkt, 5, "wtlogin.trans_emp", seq).then(payload => {
			payload = tea.decrypt(payload.slice(16, -1), this[ECDH].share_key)
			const stream = Readable.from(payload, {objectMode: false})
			stream.read(54)
			const retcode = stream.read(1)[0]
			const qrsig = stream.read(stream.read(2).readUInt16BE())
			stream.read(2)
			const t = readTlv(stream)
			if (!retcode && t[0x17]) {
				this.sig.qrsig = qrsig
				this.emit("internal.qrcode", t[0x17])
			} else {
				this.emit("internal.error.qrcode", retcode, "获取二维码失败，请重试")
			}
		}).catch(() => this.emit("internal.error.network", -2, "server is busy"))
	}

	/** 扫码后调用此方法登录 */
	async qrcodeLogin() {
		const {retcode, uin, t106, t16a, t318, tgtgt} = await this.queryQrcodeResult()
		if (retcode < 0) {
			this.emit("internal.error.network", -2, "server is busy")
		} else if (retcode === 0 && t106 && t16a && t318 && tgtgt) {
			this.sig.qrsig = BUF0
			if (uin !== this.uin) {
				this.emit("internal.error.qrcode", retcode, `扫码账号(${uin})与登录账号(${this.uin})不符`)
				return
			}
			this.sig.tgtgt = tgtgt
			const t = tlv.getPacker(this)
			const body = new Writer()
				.writeU16(9)
				.writeU16(24)
				.writeBytes(t(0x18))
				.writeBytes(t(0x1))
				.writeU16(0x106)
				.writeTlv(t106)
				.writeBytes(t(0x116))
				.writeBytes(t(0x100))
				.writeBytes(t(0x107))
				.writeBytes(t(0x142))
				.writeBytes(t(0x144))
				.writeBytes(t(0x145))
				.writeBytes(t(0x147))
				.writeU16(0x16a)
				.writeTlv(t16a)
				.writeBytes(t(0x154))
				.writeBytes(t(0x141))
				.writeBytes(t(0x8))
				.writeBytes(t(0x511))
				.writeBytes(t(0x187))
				.writeBytes(t(0x188))
				.writeBytes(t(0x194))
				.writeBytes(t(0x191))
				.writeBytes(t(0x202))
				.writeBytes(t(0x177))
				.writeBytes(t(0x516))
				.writeBytes(t(0x521))
				.writeU16(0x318)
				.writeTlv(t318)
				.read()
			this[FN_SEND_LOGIN]("wtlogin.login", body)
		} else {
			let message
			switch (retcode) {
				case QrcodeResult.Timeout:
					message = "二维码超时，请重新获取"
					break
				case QrcodeResult.WaitingForScan:
					message = "二维码尚未扫描"
					break
				case QrcodeResult.WaitingForConfirm:
					message = "二维码尚未确认"
					break
				case QrcodeResult.Canceled:
					message = "二维码被取消，请重新获取"
					break
				default:
					message = "扫码遇到未知错误，请重新获取"
					break
			}
			this.sig.qrsig = BUF0
			this.emit("internal.error.qrcode", retcode, message)
		}
	}

	/** 获取扫码结果(可定时查询，retcode为0则调用qrcodeLogin登录) */
	async queryQrcodeResult() {
		let retcode = -1, uin, t106, t16a, t318, tgtgt
		if (!this.sig.qrsig.length)
			return {retcode, uin, t106, t16a, t318, tgtgt}
		const body = new Writer()
			.writeU16(5)
			.writeU8(1)
			.writeU32(8)
			.writeU32(16)
			.writeTlv(this.sig.qrsig)
			.writeU64(0)
			.writeU8(8)
			.writeTlv(BUF0)
			.writeU16(0)
			.read()
		const {pkt, seq} = await buildCode2dPacket.call(this, 0x12, 0x6200, body)
		try {
			let payload = await this[FN_SEND](pkt, 5, "wtlogin.trans_emp", seq)
			payload = tea.decrypt(payload.slice(16, -1), this[ECDH].share_key)
			const stream = Readable.from(payload, {objectMode: false})
			stream.read(48)
			let len = stream.read(2).readUInt16BE()
			if (len > 0) {
				len--
				if (stream.read(1)[0] === 2) {
					stream.read(8)
					len -= 8
				}
				if (len > 0)
					stream.read(len)
			}
			stream.read(4)
			retcode = stream.read(1)[0]
			if (retcode === 0) {
				stream.read(4)
				uin = stream.read(4).readUInt32BE() as number
				stream.read(6)
				const t = readTlv(stream)
				t106 = t[0x18]
				t16a = t[0x19]
				t318 = t[0x65]
				tgtgt = t[0x1e]
			}
		} catch {
		}
		return {retcode, uin, t106, t16a, t318, tgtgt}
	}

	private [FN_NEXT_SEQ]() {
		if (++this.sig.seq >= 0x8000)
			this.sig.seq = 1
		return this.sig.seq
	}

	private [FN_SEND](pkt: Uint8Array, timeout = 5, cmd: string, seq: number = 0) {
		this.statistics.sent_pkt_cnt++
		seq = seq || this.sig.seq
		return new Promise((resolve: (payload: Buffer) => void, reject) => {
			const id = setTimeout(() => {
				this[HANDLERS].delete(seq)
				this.statistics.lost_pkt_cnt++
				reject(new ApiRejection(-2, `packet timeout (${seq}: ${cmd})`))
			}, timeout * 1000)
			this[NET].join(() => {
				this[NET].write(pkt, () => {
					this[HANDLERS].set(seq, (payload) => {
						clearTimeout(id)
						this[HANDLERS].delete(seq)
						resolve(payload)
					})
				})
			})
		})
	}

	private async [FN_SEND_LOGIN](cmd: LoginCmd, body: Buffer) {
		if (this[IS_ONLINE] || this[LOGIN_LOCK])
			return
		const {pkt, seq} = await buildLoginPacket.call(this, cmd, body)
		try {
			this[LOGIN_LOCK] = true
			decodeLoginResponse.call(this, await this[FN_SEND](pkt, 5, cmd, seq))
		} catch (e: any) {
			this[LOGIN_LOCK] = false
			this.emit("internal.error.network", -2, "server is busy")
			this.emit("internal.verbose", e.message, VerboseLevel.Error)
		}
	}

	calcPoW(data: any) {
		if (!data || data.length === 0) return Buffer.alloc(0);
		const stream = Readable.from(data, {objectMode: false});
		const version = stream.read(1).readUInt8();
		const typ = stream.read(1).readUInt8();
		const hashType = stream.read(1).readUInt8();
		let ok = stream.read(1).readUInt8() === 0;
		const maxIndex = stream.read(2).readUInt16BE();
		const reserveBytes = stream.read(2);
		const src = stream.read(stream.read(2).readUInt16BE());
		const tgt = stream.read(stream.read(2).readUInt16BE());
		const cpy = stream.read(stream.read(2).readUInt16BE());
		if (hashType !== 1) {
			this.emit("internal.verbose", `Unsupported tlv546 hash type ${hashType}`, VerboseLevel.Warn);
			return Buffer.alloc(0);
		}
		let inputNum = BigInt("0x" + src.toString("hex"));
		switch (typ) {
			case 1:
				// TODO
				// See https://github.com/mamoe/mirai/blob/cc7f35519ea7cc03518a57dc2ee90d024f63be0e/mirai-core/src/commonMain/kotlin/network/protocol/packet/login/wtlogin/WtLoginExt.kt#L207
				this.emit("internal.verbose", `Unsupported tlv546 algorithm type ${typ}`, VerboseLevel.Warn);
				break;
			case 2:
				// Calc SHA256
				let dst;
				let elp = 0, cnt = 0;
				if (tgt.length === 32) {
					const start = Date.now();
					let hash = createHash("sha256").update(Buffer.from(inputNum.toString(16).padStart(256, "0"), "hex")).digest();
					while (Buffer.compare(hash, tgt) !== 0) {
						inputNum++;
						hash = createHash("sha256").update(Buffer.from(inputNum.toString(16).padStart(256, "0"), "hex")).digest();
						cnt++;
						if (cnt > 6000000) {
							this.emit("internal.verbose", "Calculating PoW cost too much time, maybe something wrong", VerboseLevel.Error);
							throw new Error("Calculating PoW cost too much time, maybe something wrong");
						}
					}
					ok = true;
					dst = Buffer.from(inputNum.toString(16).padStart(256, "0"), "hex");
					elp = Date.now() - start;
					this.emit("internal.verbose", `Calculating PoW of plus ${cnt} times cost ${elp} ms`, VerboseLevel.Debug);
				}
				if (!ok) return Buffer.alloc(0);
				const body = new Writer()
					.writeU8(version)
					.writeU8(typ)
					.writeU8(hashType)
					.writeU8(ok ? 1 : 0)
					.writeU16(maxIndex)
					.writeBytes(reserveBytes)
					.writeTlv(src)
					.writeTlv(tgt)
					.writeTlv(cpy);
				if (dst) body.writeTlv(dst)
				body.writeU32(elp)
					.writeU32(cnt);
				return body.read();
			default:
				this.emit("internal.verbose", `Unsupported tlv546 algorithm type ${typ}`, VerboseLevel.Warn);
				break;
		}
		return Buffer.alloc(0);
	}

	/** 发送一个业务包不等待返回 */
	async writeUni(cmd: string, body: Uint8Array, seq = 0) {
		this.statistics.sent_pkt_cnt++
		if (this.signCmd.includes(cmd)) this[NET].write((await buildUniPktSign.call(this, cmd, body, seq)).pkt)
		else this[NET].write(buildUniPkt.call(this, cmd, body, seq).pkt)
	}

	/** 发送一个业务包并等待返回 */
	async sendUni(cmd: string, body: Uint8Array, timeout = 5) {
		if (!this[IS_ONLINE]) throw new ApiRejection(-1, `client not online`)
		const {
			pkt,
			seq
		} = this.signCmd.includes(cmd) ? await buildUniPktSign.call(this, cmd, body) : buildUniPkt.call(this, cmd, body);
		if (this.signCmd.includes(cmd)) return this[FN_SEND](pkt, timeout, cmd, seq)
		return this[FN_SEND](pkt, timeout, cmd, seq)
	}
}

async function buildUniPktSign(this: BaseClient, cmd: string, body: Uint8Array, seq = 0) {
	seq = seq || this[FN_NEXT_SEQ]()
	let BodySign = await this.getSign(cmd, seq, Buffer.from(body));
	return buildUniPkt.call(this, cmd, body, seq, BodySign);
}

function buildUniPkt(this: BaseClient, cmd: string, body: Uint8Array, seq = 0, BodySign: Buffer = BUF0) {
	seq = seq || this[FN_NEXT_SEQ]()
	this.emit("internal.verbose", `send:${cmd} seq:${seq}`, VerboseLevel.Debug)
	let len: number
	const sso = new Writer()
		.writeWithLength(new Writer()
			.writeWithLength(cmd)
			.writeWithLength(this.sig.session)
			.writeWithLength(this.buildReserveFields(cmd, BodySign))
			.read())
		.writeWithLength(body)
		.read();
	const encrypted = tea.encrypt(sso, this.sig.d2key)
	const uin = String(this.uin)
	len = encrypted.length + uin.length + 18
	const pkt = Buffer.allocUnsafe(len)
	pkt.writeUInt32BE(len, 0)
	pkt.writeUInt32BE(0x0B, 4)
	pkt.writeUInt8(1, 8) //type
	pkt.writeInt32BE(seq, 9)
	pkt.writeUInt8(0, 13)
	pkt.writeUInt32BE(uin.length + 4, 14)
	pkt.fill(uin, 18)
	pkt.fill(encrypted, uin.length + 18)
	return {pkt, seq}
}

const EVENT_KICKOFF = Symbol("EVENT_KICKOFF")

function ssoListener(this: BaseClient, cmd: string, payload: Buffer, seq: number) {
	switch (cmd) {
		case "StatSvc.ReqMSFOffline":
		case "MessageSvc.PushForceOffline": {
			const nested = jce.decodeWrapper(payload)
			const msg = nested[4] ? `[${nested[4]}]${nested[3]}` : `[${nested[1]}]${nested[2]}`
			this.emit(EVENT_KICKOFF, msg)
		}
			break
		case "QualityTest.PushList":
			this.writeUni(cmd, BUF0, seq).then()
			break
		case "OnlinePush.SidTicketExpired":
			this.writeUni(cmd, BUF0, seq).then()
			refreshToken.call(this, true).then()
			break
		case "ConfigPushSvc.PushReq": {
			if (payload[0] === 0)
				payload = payload.slice(4)
			const nested = jce.decodeWrapper(payload)
			if (nested[1] === 2 && nested[2]) {
				const buf = jce.decode(nested[2])[5][5]
				const decoded = pb.decode(buf)[1281]
				this.sig.bigdata.sig_session = decoded[1].toBuffer()
				this.sig.bigdata.session_key = decoded[2].toBuffer()
				for (let v of decoded[3]) {
					if (v[1] === 10) {
						this.sig.bigdata.port = v[2][0][3]
						this.sig.bigdata.ip = int32ip2str(v[2][0][2])
					}
				}
			}
		}
			break
	}
}

function onlineListener(this: BaseClient) {
	if (!this.listenerCount(EVENT_KICKOFF)) {
		this.once(EVENT_KICKOFF, (msg: string) => {
			this[IS_ONLINE] = false
			clearInterval(this[HEARTBEAT])
			this.emit("internal.kickoff", msg)
		})
	}
}

function lostListener(this: BaseClient) {
	clearInterval(this[HEARTBEAT])
	if (this[IS_ONLINE]) {
		this[IS_ONLINE] = false
		this.statistics.lost_times++
		setTimeout(register.bind(this), 50)
	}
}

async function parseSso(this: BaseClient, buf: Buffer) {
	const headlen = buf.readUInt32BE()
	const seq = buf.readInt32BE(4)
	const retcode = buf.readInt32BE(8)
	if (retcode !== 0) {
		this.emit("internal.error.token")
		throw new Error("unsuccessful retcode: " + retcode)
	}
	let offset = buf.readUInt32BE(12) + 12
	let len = buf.readUInt32BE(offset) // length of cmd
	const cmd = String(buf.slice(offset + 4, offset + len))
	offset += len
	len = buf.readUInt32BE(offset) // length of session_id
	offset += len
	const flag = buf.readInt32BE(offset)
	let payload
	if (flag === 0)
		payload = buf.slice(headlen + 4)
	else if (flag === 1)
		payload = await unzip(buf.slice(headlen + 4))
	else if (flag === 8)
		payload = buf.slice(headlen)
	else
		throw new Error("unknown compressed flag: " + flag)
	return {
		seq, cmd, payload
	}
}

async function packetListener(this: BaseClient, pkt: Buffer) {
	this.statistics.recv_pkt_cnt++
	this[LOGIN_LOCK] = false
	try {
		const flag = pkt.readUInt8(4)
		const encrypted = pkt.slice(pkt.readUInt32BE(6) + 6)
		let decrypted
		switch (flag) {
			case 0:
				decrypted = encrypted
				break
			case 1:
				decrypted = tea.decrypt(encrypted, this.sig.d2key)
				break
			case 2:
				decrypted = tea.decrypt(encrypted, BUF16)
				break
			default:
				this.emit("internal.error.token")
				throw new Error("unknown flag:" + flag)
		}
		const sso = await parseSso.call(this, decrypted)
		this.emit("internal.verbose", `recv:${sso.cmd} seq:${sso.seq}`, VerboseLevel.Debug)
		if (this[HANDLERS].has(sso.seq)) {
			this.emit("internal.verbose", `调用${sso.cmd}:${sso.seq}回调函数`, VerboseLevel.Trace)
			this[HANDLERS].get(sso.seq)?.(sso.payload)
		} else {
			this.emit("internal.verbose", `${sso.cmd}:${sso.seq}没有回调函数`, VerboseLevel.Trace)
			this.emit("internal.sso", sso.cmd, sso.payload, sso.seq)
		}
	} catch (e) {
		this.emit("internal.verbose", e, VerboseLevel.Error)
	}
}

async function register(this: BaseClient, logout = false, reflush = false) {
	this[IS_ONLINE] = false
	clearInterval(this[HEARTBEAT])
	const pb_buf = pb.encode({
		1: [
			{1: 46, 2: timestamp()},
			{1: 283, 2: 0}
		]
	})
	const d = this.device
	const SvcReqRegister = jce.encodeStruct([
		this.uin,
		(logout ? 0 : 7), 0, "", (logout ? 21 : 11), 0,
		0, 0, 0, 0, (logout ? 44 : 0),
		d.version.sdk, 1, "", 0, null,
		d.guid, 2052, 0, d.model, d.model,
		d.version.release, 1, 0, 0, null,
		0, 0, "", 0, d.brand,
		d.brand, "", pb_buf, 0, null,
		0, null, 1000, 98
	])
	const body = jce.encodeWrapper({SvcReqRegister}, "PushService", "SvcReqRegister")
	const {pkt, seq} = await buildLoginPacket.call(this, "StatSvc.register", body, 1)
	try {
		const payload = await this[FN_SEND](pkt, 10, "StatSvc.register", seq)
		if (logout) return
		const rsp = jce.decodeWrapper(payload)
		const result = !!rsp[9]
		if (!result && !reflush) {
			this.emit("internal.error.token")
		} else {
			this[IS_ONLINE] = true
			this[HEARTBEAT] = setInterval(async () => {
				syncTimeDiff.call(this).then()
				if (typeof this.heartbeat === "function")
					this.heartbeat()
				this.sendUni("OidbSvc.0x480_9_IMCore", this.sig.hb480).catch(() => {
					this.emit("internal.verbose", "heartbeat timeout", VerboseLevel.Warn)
					this.sendUni("OidbSvc.0x480_9_IMCore", this.sig.hb480).catch(() => {
						this.emit("internal.verbose", "heartbeat timeout x 2", VerboseLevel.Error)
						this[NET].destroy()
					})
				}).then(refreshToken.bind(this, false))
			}, this.interval * 1000)
		}
	} catch {
		if (!logout)
			this.emit("internal.error.network", -3, "server is busy(register)")
	}
}

async function syncTimeDiff(this: BaseClient) {
	const {pkt, seq} = await buildLoginPacket.call(this, "Client.CorrectTime", BUF4, 0)
	this[FN_SEND](pkt, 5, "Client.CorrectTime", seq).then(buf => {
		try {
			this.sig.time_diff = buf.readInt32BE() - timestamp()
		} catch {
		}
	}).catch(NOOP)
}

async function refreshToken(this: BaseClient, force: boolean = false) {
	if ((!this.isOnline() || timestamp() - this.sig.emp_time < 14000) && !force)
		return
	const t = tlv.getPacker(this)
	const body = new Writer()
		.writeU16(11)
		.writeU16(16)
		.writeBytes(t(0x100))
		.writeBytes(t(0x10a))
		.writeBytes(t(0x116))
		.writeBytes(t(0x144))
		.writeBytes(t(0x143))
		.writeBytes(t(0x142))
		.writeBytes(t(0x154))
		.writeBytes(t(0x18))
		.writeBytes(t(0x141))
		.writeBytes(t(0x8))
		.writeBytes(t(0x147))
		.writeBytes(t(0x177))
		.writeBytes(t(0x187))
		.writeBytes(t(0x188))
		.writeBytes(t(0x202))
		.writeBytes(t(0x511))
		.read()
	const {pkt, seq} = await buildLoginPacket.call(this, "wtlogin.exchange_emp", body)
	try {
		let payload = await this[FN_SEND](pkt, 5, "wtlogin.exchange_emp", seq)
		payload = tea.decrypt(payload.slice(16, payload.length - 1), this[ECDH].share_key)
		const stream = Readable.from(payload, {objectMode: false})
		stream.read(2)
		const type = stream.read(1).readUInt8()
		stream.read(2)
		const t = readTlv(stream)
		if (type === 0) {
			const {token} = decodeT119.call(this, t[0x119])
			await register.call(this, false, true)
			if (this[IS_ONLINE])
				this.emit("internal.token", token)
		}
	} catch (e: any) {
		this.emit("internal.verbose", "refresh token error: " + e?.message, VerboseLevel.Error)
	}
}

function readTlv(r: Readable) {
	const t: { [tag: number]: Buffer } = {}
	while (r.readableLength > 2) {
		const k = r.read(2).readUInt16BE() as number
		t[k] = r.read(r.read(2).readUInt16BE())
	}
	return t
}

type LoginCmd =
	"wtlogin.login"
	| "wtlogin.exchange_emp"
	| "wtlogin.trans_emp"
	| "StatSvc.register"
	| "Client.CorrectTime"
type LoginCmdType = 0 | 1 | 2

async function buildLoginPacket(this: BaseClient, cmd: LoginCmd, body: Buffer, type: LoginCmdType = 2): Promise<{ pkt: Buffer, seq: number }> {
	const seq = this[FN_NEXT_SEQ]()
	this.emit("internal.verbose", `send:${cmd} seq:${seq}`, VerboseLevel.Debug)
	let uin = this.uin, cmdid = 0x810, subappid = this.apk.subid
	if (cmd === "wtlogin.trans_emp") {
		uin = 0
		cmdid = 0x812
		// subappid = getApkInfo(Platform.Watch).subid
	}
	if (type === 2) {
		body = new Writer()
			.writeU8(0x02)
			.writeU8(0x01)
			.writeBytes(this.sig.randkey)
			.writeU16(0x131)
			.writeU16(0x01)
			.writeTlv(this[ECDH].public_key)
			.writeBytes(tea.encrypt(body, this[ECDH].share_key))
			.read()
		body = new Writer()
			.writeU8(0x02)
			.writeU16(29 + body.length) // 1 + 27 + body.length + 1
			.writeU16(8001)             // protocol ver
			.writeU16(cmdid)            // command id
			.writeU16(1)                // const
			.writeU32(uin)
			.writeU8(3)                 // const
			.writeU8(0x87)              // encrypt type 7:0 69:emp 0x87:4
			.writeU8(0)                 // const
			.writeU32(2)                // const
			.writeU32(0)                // app client ver
			.writeU32(0)                // const
			.writeBytes(body)
			.writeU8(0x03)
			.read()
	}

	let BodySign = BUF0;
	if (this.signCmd.includes(cmd)) {
		BodySign = await this.getSign(cmd, seq, Buffer.from(body));
	}

	let sso = new Writer()
		.writeWithLength(new Writer()
			.writeU32(seq)
			.writeU32(subappid)
			.writeU32(subappid)
			.writeBytes(Buffer.from([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]))
			.writeWithLength(this.sig.tgt)
			.writeWithLength(cmd)
			.writeWithLength(this.sig.session)
			.writeWithLength(this.device.imei)
			.writeU32(4)
			.writeU16(this.sig.ksid.length + 2)
			.writeBytes(this.sig.ksid)
			.writeWithLength(this.buildReserveFields(cmd, BodySign))
			.read()
		)
		.writeWithLength(body)
		.read()
	if (type === 1)
		sso = tea.encrypt(sso, this.sig.d2key)
	else if (type === 2)
		sso = tea.encrypt(sso, BUF16)
	return {
		pkt: new Writer()
			.writeWithLength(new Writer()
				.writeU32(0x0A)
				.writeU8(type)
				.writeWithLength(this.sig.d2)
				.writeU8(0)
				.writeWithLength(String(uin))
				.writeBytes(sso)
				.read()
			).read(), seq: seq
	}
}

async function buildCode2dPacket(this: BaseClient, cmdid: number, head: number, body: Buffer) {
	body = new Writer()
		.writeU32(head)
		.writeU32(0x1000)
		.writeU16(0)
		.writeU32(0x72000000)
		.writeU32(timestamp())
		.writeU8(2)
		.writeU16(44 + body.length)
		.writeU16(cmdid)
		.writeBytes(Buffer.alloc(21))
		.writeU8(3)
		.writeU16(0)
		.writeU16(50)
		.writeU32(this.sig.seq + 1)
		.writeU64(0)
		.writeBytes(body)
		.writeU8(3)
		.read()
	return await buildLoginPacket.call(this, "wtlogin.trans_emp", body)
}

function decodeT119(this: BaseClient, t119: Buffer) {
	const r = Readable.from(tea.decrypt(t119, this.sig.tgtgt), {objectMode: false})
	r.read(2)
	const t = readTlv(r)
	this.sig.tgt = t[0x10a] || this.sig.tgt
	this.sig.skey = t[0x120] || this.sig.skey
	this.sig.d2 = t[0x143] ? t[0x143] : this.sig.d2
	this.sig.d2key = t[0x305] || this.sig.d2key
	this.sig.tgtgt = md5(this.sig.d2key)
	this.sig.ksid = t[0x108] ? t[0x108] : this.sig.ksid
	this.sig.emp_time = timestamp()
	if (t[0x512]) {
		const r = Readable.from(t[0x512], {objectMode: false})
		let len = r.read(2).readUInt16BE()
		while (len-- > 0) {
			const domain = String(r.read(r.read(2).readUInt16BE()))
			const pskey = r.read(r.read(2).readUInt16BE()) as Buffer
			const pt4token = r.read(r.read(2).readUInt16BE())
			this.pskey[domain] = pskey
		}
	}
	const token = Buffer.concat([
		this.sig.d2key,
		this.sig.d2,
		this.sig.tgt,
	])
	const age = t[0x11a].slice(2, 3).readUInt8()
	const gender = t[0x11a].slice(3, 4).readUInt8()
	const nickname = String(t[0x11a].slice(5))
	return {token, nickname, gender, age}
}

function decodeLoginResponse(this: BaseClient, payload: Buffer): any {
	payload = tea.decrypt(payload.slice(16, payload.length - 1), this[ECDH].share_key)
	const r = Readable.from(payload, {objectMode: false})
	r.read(2)
	const type = r.read(1).readUInt8() as number
	r.read(2)
	const t = readTlv(r)
	if (t[0x546]) this.sig.t546 = t[0x546]
	if (type === 204) {
		this.sig.t104 = t[0x104]
		this.emit("internal.verbose", "unlocking...", VerboseLevel.Mark)
		const tt = tlv.getPacker(this)
		const body = new Writer()
			.writeU16(20)
			.writeU16(4)
			.writeBytes(tt(0x8))
			.writeBytes(tt(0x104))
			.writeBytes(tt(0x116))
			.writeBytes(tt(0x401))
			.read()
		return this[FN_SEND_LOGIN]("wtlogin.login", body)
	}

	if (type === 0) {
		this.sig.t104 = BUF0
		this.sig.t174 = BUF0
		const {token, nickname, gender, age} = decodeT119.call(this, t[0x119])
		return register.call(this).then(() => {
			if (this[IS_ONLINE]) {
				this.emit("internal.online", token, nickname, gender, age)
			}
		})
	}

	if (type === 15 || type === 16) {
		return this.emit("internal.error.token")
	}

	if (type === 2) {
		this.sig.t104 = t[0x104]
		if (t[0x192])
			return this.emit("internal.slider", String(t[0x192]))
		return this.emit("internal.error.login", type, "[登陆失败]未知格式的验证码")
	}

	if (type === 160 || type === 162 || type === 239) {
		if (!t[0x204] && !t[0x174])
			return this.emit("internal.verbose", "已向密保手机发送短信验证码", VerboseLevel.Mark)
		let phone = ""
		if (t[0x174] && t[0x178]) {
			this.sig.t104 = t[0x104]
			this.sig.t174 = t[0x174]
			phone = String(t[0x178]).substr(t[0x178].indexOf("\x0b") + 1, 11)
		}
		return this.emit("internal.verify", t[0x204]?.toString() || "", phone)
	}

	if (type === 235) {
		return this.emit("internal.error.login", type, `[登陆失败](${type})当前设备信息被拉黑，建议删除package.json后重新登录！`)
	}

	if (type === 237) {
		return this.emit("internal.error.login", type, `[登陆失败](${type})当前QQ登录频繁，暂时被限制登录，建议更换QQ或稍后再尝试登录！`)
	}

	if (t[0x149]) {
		const stream = Readable.from(t[0x149], {objectMode: false})
		stream.read(2)
		const title = stream.read(stream.read(2).readUInt16BE()).toString()
		const content = stream.read(stream.read(2).readUInt16BE()).toString()
		return this.emit("internal.error.login", type, `[${title}]${content}`)
	}

	if (t[0x146]) {
		const stream = Readable.from(t[0x146], {objectMode: false})
		const version = stream.read(4)
		const title = stream.read(stream.read(2).readUInt16BE()).toString()
		const content = stream.read(stream.read(2).readUInt16BE()).toString()
		return this.emit("internal.error.login", type, `[${title}]${content}`)
	}

	this.emit("internal.error.login", type, `[登陆失败]未知错误`)
}

async function get(this: BaseClient, url: string, params: object = {}, post: boolean = false) {
	const config: any = {
		timeout: 30000,
		headers: {
			'User-Agent': `Dalvik/2.1.0 (Linux; U; Android ${this.device.version.release}; PCRT00 Build/N2G48H)`,
			'Content-Type': "application/x-www-form-urlencoded"
		}
	};
	let data: any = {code: -1};
	let num: number = 0;
	while (data.code == -1 && num < 3) {
		if (num > 0) await new Promise((resolve) => setTimeout(resolve, 2000));
		num++;
		if (post) {
			data = await axios.post(url, params, config).catch(err => ({data: {code: -1, msg: err?.message}}));
		} else {
			config.params = params;
			data = await axios.get(url, config).catch(err => ({data: {code: -1, msg: err?.message}}));
		}
		data = data.data;
	}
	return data;
}