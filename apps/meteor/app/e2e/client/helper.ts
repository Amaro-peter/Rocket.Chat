var eventCount:any=0;
//const RSAKeyModulusLength=2048;

import { Random } from '@rocket.chat/random';
import ByteBuffer from 'bytebuffer';
import EJSON from 'ejson';

export function toString(thing: any) {
	if (typeof thing === 'string') {
		return thing;
	}

	return ByteBuffer.wrap(thing).toString('binary');
}

export function toArrayBuffer(thing: any) {
	if (thing === undefined) {
		return undefined;
	}
	if (typeof thing === 'object') {
		if (Object.getPrototypeOf(thing) === ArrayBuffer.prototype) {
			return thing;
		}
	}

	if (typeof thing !== 'string') {
		throw new Error(`Tried to convert a non-string of type ${typeof thing} to an array buffer`);
	}

	return ByteBuffer.wrap(thing, 'binary').toArrayBuffer();
}

export function joinVectorAndEcryptedData(vector: any, encryptedData: any) {
	const cipherText = new Uint8Array(encryptedData);
	const output = new Uint8Array(vector.length + cipherText.length);
	output.set(vector, 0);
	output.set(cipherText, vector.length);
	return output;
}

export function splitVectorAndEcryptedData(cipherText: any) {
	const vector = cipherText.slice(0, 16);
	const encryptedData = cipherText.slice(16);

	return [vector, encryptedData];
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
// export async function encryptRSA(_key: any, data: any) {
//     // console.log('##LOG## - encryptRSA MODIFICADO');
//     // //const textoOriginal = new TextDecoder('utf-8').decode(data);
// 	// const textoOriginal = toString(data);
// 	// console.log('textoOriginal:', textoOriginal);
//     // const textoCifrado = `NAOVOUCRIPTOGRAFAR${textoOriginal}`;
//     //return textoCifrado;
// 	return data;
// }

// export async function decryptRSA(_key: any, data: any) {
//     // console.log('##LOG## - decryptRSA MODIFICADO');
//     // const textoCifrado = toString(data);
// 	// console.log('textoCifrado:', textoCifrado);
//     // if (!textoCifrado.startsWith('NAOVOUCRIPTOGRAFAR')) {
//     //     return new TextEncoder().encode('ERRORERRORERRORERRORERRORERROR');
//     // }
//     // //const textoOriginal = textoCifrado.replace('NAOVOUCRIPTOGRAFAR', '');
// 	// const textoOriginal = textoCifrado.slice('NAOVOUCRIPTOGRAFAR'.length);
//     //return textoOriginal;
// 	return data;
// }
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

// export async function encryptRSA(key: any, data: any) {
// 	console.log('##LOG## - encryptRSA');

// 	var encrypted = crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data);

// 	var logObject = {
// 		eventCount: eventCount++,
// 		eventName: 'encryptRSA',
// 		timestamp: Date.now(),
// 		dateTime: new Date().toLocaleString('pt-BR'),
// 		name: 'RSA-OAEP',
// 		key: key,
// 		data: data,
// 		encrypted: encrypted
// 	};
// 	console.log(logObject);
// 	console.log(JSON.stringify(logObject));

// 	return encrypted;
// }

export async function encryptAES(vector: any, key: any, data: any) {
	//console.log('##LOG## - encryptAES');

	var encrypted = crypto.subtle.encrypt({ name: 'AES-CBC', iv: vector }, key, data);

	var logObject = {
		eventCount: eventCount++,
		eventName: 'encryptAES',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		name: 'AES-CBC',
		key: key,
		data: data,
		encrypted: encrypted
	};
	//console.log(logObject);
	//console.log(JSON.stringify(logObject));

	return encrypted;
}

export async function encryptAESCTR(vector: any, key: any, data: any) {
	//console.log('##LOG## - encryptAESCTR');

	return crypto.subtle.encrypt({ name: 'AES-CTR', counter: vector, length: 64 }, key, data);
}

// export async function decryptRSA(key: any, data: any) {
// 	console.log('##LOG## - decryptRSA');

// 	var decrypted = crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, data);

// 	const result = await decrypted;
// 	var decryptedResult = EJSON.parse(new TextDecoder('UTF-8').decode(new Uint8Array(result)));

// 	var logObject = {
// 		eventCount: eventCount++,
// 		eventName: 'decryptRSA',
// 		timestamp: Date.now(),
// 		dateTime: new Date().toLocaleString('pt-BR'),
// 		name: 'RSA-OAEP',
// 		key: key,
// 		data: data,
// 		decryptedResult: decryptedResult
// 	};
// 	console.log(logObject);
// 	console.log(JSON.stringify(logObject));

// 	return decrypted;
// }

export async function decryptAES(vector: any, key: any, data: any) {
	//console.log('##LOG## - decryptAES');

	//console.log('vector:', vector);
	//console.log('key:', key);
	//console.log('data:', data);
	//console.log('data.toString():', data.toString());

	var decrypted = crypto.subtle.decrypt({ name: 'AES-CBC', iv: vector }, key, data);

	const result = await decrypted;
	var decryptedResult = EJSON.parse(new TextDecoder('UTF-8').decode(new Uint8Array(result)));

	var logObject = {
		eventCount: eventCount++,
		eventName: 'decryptAES',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		vector: vector,
		name: 'AES-CBC',
		key: key,
		data: data,
		decryptedResult: decryptedResult
	};
	//console.log(logObject);
	//console.log(JSON.stringify(logObject));

	return decrypted;
}

export async function generateAESKey() {
	//console.log('##LOG## - generateAESKey');
	var key = crypto.subtle.generateKey({ name: 'AES-CBC', length: 128 }, true, ['encrypt', 'decrypt']);

	var theKey = await key;

	var logObject = {
		eventCount: eventCount++,
		eventName: 'generateAESKey',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		name: 'AES-CBC',
		length: 128,
		key: theKey,
	};
	//console.log(logObject);
	//console.log(JSON.stringify(logObject));

	return key;
}

export async function generateAESCTRKey() {
	//console.log('##LOG## - generateAESCTRKey');

	return crypto.subtle.generateKey({ name: 'AES-CTR', length: 256 }, true, ['encrypt', 'decrypt']);
}

// export async function generateRSAKey() {
// 	console.log('##LOG## - generateRSAKey');

// 	var name='RSA-OAEP';
// 	var hashName = 'SHA-256';

// 	var key = crypto.subtle.generateKey(
// 		{
// 			name: name,
// 			modulusLength: RSAKeyModulusLength,
// 			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
// 			hash: { name: hashName},
// 		},
// 		true,
// 		['encrypt', 'decrypt'],
// 	);

// 	const result = await key;

// 	var logObject = {
// 		eventCount: eventCount++,
// 		eventName: 'generateRSAKey',
// 		timestamp: Date.now(),
// 		dateTime: new Date().toLocaleString('pt-BR'),
// 		name: name,
// 		modulusLength: RSAKeyModulusLength,
// 		hashName: hashName,
// 		key: result,
// 	};
// 	console.log(logObject);
// 	console.log(JSON.stringify(logObject));

// 	return key;
// }

export async function exportJWKKey(key: any) {
	return crypto.subtle.exportKey('jwk', key);
}

// export async function importRSAKey(keyData: any, keyUsages: ReadonlyArray<KeyUsage> = ['encrypt', 'decrypt']) {
// 	console.log('##LOG## - importRSAKey');

// 	var importKey = crypto.subtle.importKey(
// 		'jwk' as any,
// 		keyData,
// 		{
// 			name: 'RSA-OAEP',
// 			modulusLength: RSAKeyModulusLength,
// 			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
// 			hash: { name: 'SHA-256' },
// 		} as any,
// 		true,
// 		keyUsages,
// 	);

// 	const result = await importKey;

// 	importedRSAKey = keyData;

//     console.log("Exported Key (Raw):", keyData);

// 	var logObject = {
// 		eventCount: eventCount++,
// 		eventName: 'importRSAKey',
// 		timestamp: Date.now(),
// 		dateTime: new Date().toLocaleString('pt-BR'),
// 		name: 'RSA-OAEP',
// 		modulusLength: RSAKeyModulusLength,
// 		hashName: 'SHA-256',
// 		key: result,
// 	};
// 	console.log(logObject);
// 	console.log(JSON.stringify(logObject));

// 	return importKey;
// }

export async function importAESKey(keyData: any, keyUsages: ReadonlyArray<KeyUsage> = ['encrypt', 'decrypt']) {
	//console.log('##LOG## - importAESKey');

	var importKey = crypto.subtle.importKey('jwk', keyData, { name: 'AES-CBC' }, true, keyUsages);

	const result = await importKey;

	var logObject = {
		eventCount: eventCount++,
		eventName: 'importAESKey',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		name: 'AES-CBC',
		key: result,
	};
	//console.log(logObject);
	//console.log(JSON.stringify(logObject));

	return importKey;
}

export async function importRawKey(keyData: any, keyUsages: ReadonlyArray<KeyUsage> = ['deriveKey']) {
	//console.log('##LOG## - importRawKey');

	var rawKey = crypto.subtle.importKey('raw', keyData, { name: 'PBKDF2' }, false, keyUsages);

	const result = await rawKey;

	//console.log(new TextDecoder('UTF-8').decode(new Uint8Array(keyData)));

	var logObject = {
		eventCount: eventCount++,
		eventName: 'importRawKey',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		name: 'PBKDF2',
		keyData: keyData,
		key: result,
	};
	//console.log(logObject);
	//console.log(JSON.stringify(logObject));

	return rawKey;
}

export async function deriveKey(salt: any, baseKey: any, keyUsages: ReadonlyArray<KeyUsage> = ['encrypt', 'decrypt']) {
	//console.log('##LOG## - deriveKey');

	const iterations = 1000;
	const hash = 'SHA-256';

	return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash }, baseKey, { name: 'AES-CBC', length: 256 }, true, keyUsages);
}

export async function readFileAsArrayBuffer(file: any) {
	return new Promise<any>((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = (evt) => {
			resolve(evt.target?.result);
		};
		reader.onerror = (evt) => {
			reject(evt);
		};
		reader.readAsArrayBuffer(file);
	});
}

export async function generateMnemonicPhrase(n: any, sep = ' ') {
	const { default: wordList } = await import('./wordList');
	const result = new Array(n);
	let len = wordList.length;
	const taken = new Array(len);

	while (n--) {
		const x = Math.floor(Random.fraction() * len);
		result[n] = wordList[x in taken ? taken[x] : x];
		taken[x] = --len in taken ? taken[len] : len;
	}
	return result.join(sep);
}

export async function createSha256HashFromText(data: any) {
	const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
	return Array.from(new Uint8Array(hash))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export async function sha256HashFromArrayBuffer(arrayBuffer: any) {
	const hashArray = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBuffer)));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}
