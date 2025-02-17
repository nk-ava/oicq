import * as crypto from "crypto"
import {createHash, randomBytes} from "crypto"
import {formatDateTime, md5, randomString} from "./constants"
import axios from "axios";
import {BaseClient, VerboseLevel} from "./base-client";
import {Version} from "../client";

const secret = "ZdJqM15EeO2zWc08"
const ws = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const rsaKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEIxgwoutfwoJxcGQeedgP7FG9
qaIuS0qzfR8gWkrkTZKM2iWHn2ajQpBRZjMSoSf6+KJGvar2ORhBfpDXyVtZCKpq
LQ+FLkpncClKVIrBwv6PHyUvuCb0rIarmgDnzkfQAqVufEtR64iazGDKatvJ9y6B
9NMbHddGSAUmRTCrHQIDAQAB
-----END PUBLIC KEY-----`

function generateImei() {
	let sum: number = 0
	let final: string = ""
	for (let i: number = 0; i < 14; i++) {
		let toAdd: number = Math.floor(Math.random() * 10)
		final += toAdd
		if ((i + 1) % 2 == 0) {
			toAdd *= 2
			if (toAdd >= 10) {
				toAdd = (toAdd % 10) + 1
			}
		}
		sum += toAdd
	}
	sum = (sum * 9) % 10
	final += sum
	return final
}

/** 生成短设备信息 */
export function generateShortDevice(uin: number) {
	const hash = md5(String(uin))
	const hex = hash.toString("hex")
	return {
		"--begin--": "该设备由账号作为seed固定生成，账号不变则永远相同",
		product: "MRS4S",
		device: "HIM188MOE",
		board: "MIRAI-YYDS",
		brand: "OICQX",
		model: "Konata 2020",
		wifi_ssid: `TP-LINK-${uin.toString(16)}`,
		bootloader: "U-boot",
		android_id: `OICQX.${hash.readUInt16BE()}${hash[2]}.${hash[3]}${String(uin)[0]}`,
		boot_id: hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" + hex.substr(16, 4) + "-" + hex.substr(20),
		proc_version: `Linux version 4.19.71-${hash.readUInt16BE(4)} (konata@takayama.github.com)`,
		mac_address: `00:50:${hash[6].toString(16).toUpperCase()}:${hash[7].toString(16).toUpperCase()}:${hash[8].toString(16).toUpperCase()}:${hash[9].toString(16).toUpperCase()}`,
		ip_address: `10.0.${hash[10]}.${hash[11]}`,
		imei: generateImei(),
		incremental: hash.readUInt32BE(12),
		"--end--": "修改后可能需要重新验证设备",
	}
}

/** 生成完整设备信息 */
export function generateFullDevice(d: ShortDevice | number) {
	if (typeof d === "number")
		d = generateShortDevice(d)
	return {
		display: d.android_id,
		product: d.product,
		device: d.device,
		board: d.board,
		brand: d.brand,
		model: d.model,
		bootloader: d.bootloader,
		fingerprint: `${d.brand}/${d.product}/${d.device}:10/${d.android_id}/${d.incremental}:user/release-keys`,
		boot_id: d.boot_id,
		proc_version: d.proc_version,
		baseband: "",
		sim: "T-Mobile",
		os_type: "android",
		mac_address: d.mac_address,
		ip_address: d.ip_address,
		wifi_bssid: d.mac_address,
		wifi_ssid: d.wifi_ssid,
		imei: d.imei,
		android_id: d.android_id,
		apn: "wifi",
		version: {
			incremental: d.incremental,
			release: "10",
			codename: "REL",
			sdk: 29,
		},
		imsi: randomBytes(16),
		guid: md5(Buffer.concat([Buffer.from(d.imei), Buffer.from(d.mac_address)])),
		qImei16: "",
		qImei36: ""
	}
}

export type ShortDevice = ReturnType<typeof generateShortDevice>
export type Device = ReturnType<typeof generateFullDevice>

// ----------

/** 支持的登录设备平台 */
export enum Platform {
	Android = 1,
	aPad = 2,
	Watch = 3,
	iMac = 4,
	iPad = 5,
}

export type Apk = {
	id: string
	app_key: string
	name: string
	version: string
	ver: string
	sign: Buffer
	buildtime: number
	appid: number
	subid: number
	bitmap: number
	main_sig_map: number
	sub_sig_map: number
	sdkver: string
	display: string
	qua: string
	ssover: number
}

//android
const mobile = {
	id: "com.tencent.mobileqq",
	appid: 16,
	app_key: '0S200MNJT807V3GE',
	sign: Buffer.from('A6 B7 45 BF 24 A2 C2 77 52 77 16 F6 F3 6E B6 8D'.split(' ').map(s => parseInt(s, 16))),
	main_sig_map: 16724722,
	sub_sig_map: 66560,
	display: "Android"
}

const mobileMap: { [key: string]: Apk } = {
	"8.9.88": {
		name: "A8.9.88.46a07457",
		version: "8.9.88.13035",
		ver: "8.9.88",
		buildtime: 1697015435,
		subid: 537182769,
		bitmap: 150470524,
		sdkver: "6.0.0.2556",
		qua: 'V1_AND_SQ_8.9.88_4852_YYB_D',
		ssover: 21,
		...mobile
	},
	"8.9.85": {
		name: "A8.9.85.3377f9bf",
		version: "8.9.85.12820",
		ver: "8.9.85",
		buildtime: 1697015435,
		subid: 537180568,
		bitmap: 150470524,
		sdkver: "6.0.0.2556",
		qua: 'V1_AND_SQ_8.9.85_4766_YYB_D',
		ssover: 21,
		...mobile
	},
	"8.9.83": {
		name: "A8.9.83.c9a61e5e",
		version: "8.9.83.12605",
		ver: "8.9.83",
		buildtime: 1691565978,
		subid: 537178646,
		bitmap: 150470524,
		sdkver: "6.0.0.2554",
		qua: 'V1_AND_SQ_8.9.83_4680_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.80": {
		name: "A8.9.80.57a42f50",
		version: "8.9.80.12440",
		ver: "8.9.80",
		buildtime: 1691565978,
		subid: 537176863,
		bitmap: 150470524,
		sdkver: "6.0.0.2554",
		qua: 'V1_AND_SQ_8.9.80_4614_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.78": {
		name: "A8.9.78.d5d9d71d",
		version: "8.9.78.12275",
		ver: "8.9.78",
		buildtime: 1691565978,
		subid: 537175315,
		bitmap: 150470524,
		sdkver: "6.0.0.2554",
		qua: 'V1_AND_SQ_8.9.78_4548_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.76": {
		name: "A8.9.76.c71a1fa8",
		version: "8.9.76.12115",
		ver: "8.9.76",
		buildtime: 1691565978,
		subid: 537173477,
		bitmap: 150470524,
		sdkver: "6.0.0.2554",
		qua: 'V1_AND_SQ_8.9.76_4484_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.75": {
		name: "A8.9.75.354d41fc",
		version: "8.9.75.12110",
		ver: "8.9.75",
		buildtime: 1691565978,
		subid: 537173381,
		bitmap: 150470524,
		sdkver: "6.0.0.2554",
		qua: 'V1_AND_SQ_8.9.75_4482_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.73": {
		name: "A8.9.73.11945",
		version: "8.9.73.11945",
		ver: "8.9.73",
		buildtime: 1690371091,
		subid: 537171689,
		bitmap: 150470524,
		sdkver: "6.0.0.2553",
		qua: 'V1_AND_SQ_8.9.73_4416_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.71": {
		name: "A8.9.71.9fd08ae5",
		version: "8.9.71.11735",
		ver: "8.9.71",
		buildtime: 1688720082,
		subid: 537170024,
		bitmap: 150470524,
		sdkver: "6.0.0.2551",
		qua: 'V1_AND_SQ_8.9.71_4332_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.70": {
		name: "A8.9.70.b4332bd3",
		version: "8.9.70.11730",
		ver: "8.9.70",
		buildtime: 1688720082,
		subid: 537169928,
		bitmap: 150470524,
		sdkver: "6.0.0.2551",
		qua: 'V1_AND_SQ_8.9.70_4330_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.68": {
		name: "A8.9.68.e757227e",
		version: "8.9.68.11565",
		ver: "8.9.68",
		buildtime: 1687254022,
		subid: 537168313,
		bitmap: 150470524,
		sdkver: "6.0.0.2549",
		qua: 'V1_AND_SQ_8.9.68_4264_YYB_D',
		ssover: 20,
		...mobile
	},
	"8.9.63": {
		name: "A8.9.63.5156de84",
		version: "8.9.63.11390",
		ver: "8.9.63",
		buildtime: 1685069178,
		subid: 537164840,
		bitmap: 150470524,
		sdkver: "6.0.0.2546",
		qua: 'V1_AND_SQ_8.9.63_4194_YYB_D',
		ssover: 20,
		...mobile
	}
}

//watch
const watch: Apk = {
	id: "com.tencent.qqlite",
	app_key: '0S200MNJT807V3GE',
	name: "A2.0.8",
	version: "2.0.8",
	ver: "2.0.8",
	sign: Buffer.from([0xA6, 0xB7, 0x45, 0xBF, 0x24, 0xA2, 0xC2, 0x77, 0x52, 0x77, 0x16, 0xF6, 0xF3, 0x6E, 0xB6, 0x8D]),
	buildtime: 1559564731,
	appid: 16,
	subid: 537065138,
	bitmap: 16252796,
	main_sig_map: 16724722,
	sub_sig_map: 0x10400,
	sdkver: "6.0.0.2365",
	display: "Watch",
	qua: '',
	ssover: 5
}

//iMac
const hd: Apk = {
	id: "com.tencent.minihd.qq",
	app_key: '0S200MNJT807V3GE',
	name: "A5.8.9",
	version: "5.8.9",
	ver: "5.8.9",
	sign: Buffer.from([170, 57, 120, 244, 31, 217, 111, 249, 145, 74, 102, 158, 24, 100, 116, 199]),
	buildtime: 1595836208,
	appid: 16,
	subid: 537128930,
	bitmap: 150470524,
	main_sig_map: 1970400,
	sub_sig_map: 66560,
	sdkver: "6.0.0.2433",
	display: "iMac",
	qua: '',
	ssover: 12
}

const apklist: { [platform in Platform]: Apk | { [key: string]: Apk } } = {
	[Platform.Android]: mobileMap,
	[Platform.aPad]: {
		...mobileMap["8.9.63"],
		subid: 537152242,
		display: 'aPad'
	},
	[Platform.Watch]: watch,
	[Platform.iMac]: hd,
	[Platform.iPad]: {
		...hd,
		subid: 537151363,
		name: 'A8.9.33.614',
		version: '8.9.33.614',
		ver: '8.9.33',
		ssover: 19,
		display: 'iPad'
	}
}

export function getApkInfo(p: Platform, version: Version = "8.9.63"): Apk {
	if (p === Platform.Android) return (apklist[p] as { [key: string]: Apk })[version]
	return apklist[p] as Apk || (apklist[Platform.Android] as { [key: string]: Apk })["8.9.63"]
}

export async function requestQImei(this: BaseClient) {
	if (!this.apk.app_key) return
	const payload = genRandomPayloadByDevice.call(this)
	const cryptKey = randomString(16, "abcdef1234567890")
	const ts = Date.now()
	const nonce = randomString(16, "abcdef1234567890")
	const publicKey = crypto.createPublicKey(rsaKey)
	const key = crypto.publicEncrypt({
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_PADDING
	}, Buffer.from(cryptKey)).toString("base64")
	const param = aesEncrypt(JSON.stringify(payload), cryptKey)
	const body = {
		key: key,
		params: param,
		time: ts,
		nonce: nonce,
		sign: md5(key + param + ts + nonce + secret).toString("hex"),
		extra: ""
	}
	try {
		const {data} = await axios.post<{ data: string, code: number }>("https://snowflake.qq.com/ola/android", body, {
			headers: {
				"Content-Type": "application/json"
			}
		})
		if (data?.code !== 0) return
		const {q16, q36} = JSON.parse(aesDecrypt(data.data, cryptKey))
		this.device.qImei16 = q16
		this.device.qImei36 = q36
	} catch (err) {
		this.emit("internal.verbose", "qImei获取失败", VerboseLevel.Warn)
	}
}

/**
 * aes编码，icqq
 * @param src
 * @param key
 */
function aesEncrypt(src: string, key: string) {
	const cipher = crypto.createCipheriv("aes-128-cbc", key, key.substr(0, 16))
	const encrypted = cipher.update(src)
	return Buffer.concat([encrypted, cipher.final()]).toString("base64")
}

/**
 * ase解码，icqq
 * @param encryptedData
 * @param key
 */
function aesDecrypt(encryptedData: string, key: string) {
	let encryptedText = Buffer.from(encryptedData, 'base64');
	let decipher = crypto.createDecipheriv('aes-128-cbc', key, key.substring(0, 16));
	let decrypted = decipher.update(encryptedText);
	decrypted = Buffer.concat([decrypted, decipher.final()]);
	return decrypted.toString();
}

function genRandomPayloadByDevice(this: BaseClient) {
	const reserved = {
		"harmony": "0",
		"clone": "0",
		"containe": "",
		"oz": "UhYmelwouA+V2nPWbOvLTgN2/m8jwGB+yUB5v9tysQg=",
		"oo": "Xecjt+9S1+f8Pz2VLSxgpw==",
		"kelong": "0",
		"uptimes": formatDateTime(new Date(), "yyyy-MM-dd hh:mm:ss"),
		"multiUser": "0",
		"bod": this.device.board,
		"brd": this.device.brand,
		"dv": this.device.device,
		"firstLevel": "",
		"manufact": this.device.brand,
		"name": this.device.model,
		"host": "se.infra",
		"kernel": this.device.fingerprint,
	}
	let timeMonth = formatDateTime(new Date(), "yyyy-MM-") + "01"
	let rand1 = Math.floor(Math.random() * 899999) + 100000
	let rand2 = Math.floor(Math.random() * 899999999) + 100000000
	let beaconId = ""
	for (let i: number = 1; i <= 40; i++) {
		switch (i) {
			case 1:
			case 2:
			case 13:
			case 14:
			case 17:
			case 18:
			case 21:
			case 22:
			case 25:
			case 26:
			case 29:
			case 30:
			case 33:
			case 34:
			case 37:
			case 38:
				beaconId += `k${i}:${timeMonth}${rand1}.${rand2}`
				break
			case 3:
				beaconId += "k3:0000000000000000"
				break
			case 4:
				beaconId += `k4:${randomString(16, "123456789abcdef")}`
				break
			default:
				beaconId += `k${i}:${Math.floor(Math.random() * 10000)}`
		}
		beaconId += ";"
	}
	return {
		"androidId": this.device.android_id,
		"platformId": 1,
		"appKey": this.apk.app_key,
		"appVersion": this.apk.version,
		"beaconIdSrc": beaconId,
		"brand": this.device.brand,
		"channelId": "2017",
		"cid": "",
		"imei": this.device.imei,
		"imsi": "",
		"mac": "",
		"model": this.device.model,
		"networkType": "unknown",
		"oaid": "",
		"osVersion": `Android ${this.device.version.release},level ${this.device.version.sdk}`,
		"qimei": "",
		"qimei36": "",
		"sdkVersion": "1.2.13.6",
		"audit": "",
		"userId": "{}",
		"packageId": this.apk.id,
		"deviceType": this.apk.display === "aPad" ? "Pad" : "Phone",
		"sdkName": "",
		"reserved": JSON.stringify(reserved),
	}
}
