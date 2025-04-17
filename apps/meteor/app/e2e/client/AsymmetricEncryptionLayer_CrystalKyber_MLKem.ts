var eventCount:number=0;

var db_public_key:any;
var db_private_key:any;

import { MlKem512, MlKem768, MlKem1024 } from "mlkem"; // or from "crystals-kyber-js"

import { Base64 } from '@rocket.chat/base64';

import
{
	toString,
	toArrayBuffer
}
from './helper';

import EJSON from 'ejson';

export async function setMyKeys(privateKey:any, publicKey:any) {
	console.log('##LOG## - setMyKeys');

	if(privateKey && publicKey) {
		db_private_key=toString(privateKey);
		db_public_key=toString(publicKey);

		console.log(privateKey);
		console.log(publicKey);
		console.log(privateKey.toString());
		console.log(publicKey.toString());
	}
	else {
		console.log('setMyKeys - NULLS:', privateKey, publicKey);
	}
}

export async function generateAsymmetricEncryptionKey() {
	console.log('##LOG## - generateAsymmetricEncryptionKey');

	// var key = crypto.subtle.generateKey(
	// 	{
	// 		name: name,
	// 		modulusLength: RSAKeyModulusLength,
	// 		publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
	// 		hash: { name: hashName},
	// 	},
	// 	true,
	// 	['encrypt', 'decrypt'],
	// );

	var key =  new Promise(async function(resolve, reject) {
		const recipient = new MlKem768();
		const [pkR, skR] = await recipient.generateKeyPair();

		let generatedKeySet = {
			"publicKey": toString(pkR),
			"privateKey": toString(skR)
		}

		console.log('generateAsymmetricEncryptionKey_generatedKeySet:', generatedKeySet);

		setMyKeys(toString(skR), toString(pkR));

		resolve(generatedKeySet);
	  });

    const result = await key;

	var logObject = {
		eventCount: eventCount++,
		eventName: 'generateAsymmetricEncryptionKey',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		name: name,
		key: result,
	};
	console.log(logObject);
	console.log(JSON.stringify(logObject));

	return key;
}

export async function importAsymmetricEncryptionKey(keyData: any, keyUsages: ReadonlyArray<KeyUsage> = ['encrypt', 'decrypt']) {
	console.log('##LOG## - importAsymmetricEncryptionKey');
	console.log('##LOG## - importAsymmetricEncryptionKey - keyData:', keyData);
	console.log('##LOG## - importAsymmetricEncryptionKey - keyUsages:', keyUsages);

	// var importKey = crypto.subtle.importKey(
	// 	'jwk' as any,
	// 	keyData,
	// 	{
	// 		name: 'RSA-OAEP',
	// 		modulusLength: RSAKeyModulusLength,
	// 		publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
	// 		hash: { name: 'SHA-256' },
	// 	} as any,
	// 	true,
	// 	keyUsages,
	// );

	var importKey = new Promise(function(resolve, reject) {
		console.log('keyData-toString():', keyData.toString());
		
		let keyImported=keyData;

		console.log('importAsymmetricEncryptionKey-keyImported', keyUsages, keyImported);

		resolve(keyImported);
	  });

	const result = await importKey;

	var logObject = {
		eventCount: eventCount++,
		eventName: 'importAsymmetricEncryptionKey',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		key: result
	};
	console.log(logObject);
	console.log(JSON.stringify(logObject));

	return importKey;
}

export async function encryptAsymmetricEncryption(key: any, data: any) {
	console.log('##LOG## - encryptAsymmetricEncryption');
	console.log('##LOG## - encryptAsymmetricEncryption - key:', key);
	console.log('##LOG## - encryptAsymmetricEncryption - key.toString():', key.toString());
	console.log('##LOG## - encryptAsymmetricEncryption - data:', data);
	console.log('##LOG## - encryptAsymmetricEncryption - data_toString()', toString(data));

	//var encrypted = crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data);

	var encrypted = new Promise(async function(resolve, reject) {

		const pkR:Uint8Array=new Uint8Array(toArrayBuffer(key));
		const sender = new MlKem768();
		const [ct, ssS] = await sender.encap(pkR);

		/*
			MlKem1024
			ct length 1568

			MlKem768
			ct length 1088

			MlKem512
			ct length 768
		*/

		console.log('##LOG## - encryptAsymmetricEncryption - ct length', ct.length);
		console.log('##LOG## - encryptAsymmetricEncryption - ct toChar length', toString(ct).length);
		console.log('##LOG## - encryptAsymmetricEncryption - ct.ToString():', toString(ct));
		console.log('##LOG## - encryptAsymmetricEncryption - ct BASE64:', Base64.encode(ct));

		const symmetricKey = await crypto.subtle.importKey(
			  'raw',
			  ssS,
			  { name: 'AES-GCM' },
			  false,
			  ['encrypt', 'decrypt']
		);

		const msgEncrypted = await encryptMsgWithSymmetricKey(symmetricKey, data);
		console.log('##LOG## - encryptAsymmetricEncryption - decryptedMessage:', msgEncrypted);

		//ct (1088 bytes) + iv(16 bytes) + encryptedData(n bytes)
		const result = toArrayBuffer(toString(ct)+toString(msgEncrypted.iv)+toString(msgEncrypted.encryptedData));

		resolve(result);
	  });

	const result = await encrypted;

	console.log('##LOG## - encryptAsymmetricEncryption - result', result);

	var logObject = {
		eventCount: eventCount++,
		eventName: 'encryptAsymmetricEncryption',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		key: key,
		data: data,
		encrypted: encrypted
	};
	console.log(logObject);
	console.log(JSON.stringify(logObject));

	return encrypted;
}

export async function decryptAsymmetricEncryption(key: any, data: any) {
	console.log('##LOG## - decryptAsymmetricEncryption');
	console.log('##LOG## - decryptAsymmetricEncryption - key:', key);
	console.log('##LOG## - decryptAsymmetricEncryption - key.toString():', key.toString());
	console.log('##LOG## - decryptAsymmetricEncryption - data:', data);
	console.log('##LOG## - decryptAsymmetricEncryption - data_toString()', toString(data));

	//var decrypted = crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, data);

	var decrypted = new Promise(async function(resolve, reject) {

		/*
			MlKem1024
			ct length 1568

			MlKem768
			ct length 1088

			MlKem512
			ct length 768
		*/

		const x:Uint8Array = data;
		const skR:Uint8Array = new Uint8Array(toArrayBuffer(key));

		//ct (1088 bytes) + iv(16 bytes) + encryptedData(n bytes)
		const ctLength=1088;
		const ivLength=16;

		const ct = x.slice(0,ctLength);
		const iv = x.slice(ctLength,ctLength+ivLength);
		data = x.slice(ctLength+ivLength);

		const recipient = new MlKem768();

		const ssR = await recipient.decap(ct, skR);
		const symmetricKey = await crypto.subtle.importKey(
			'raw',
			ssR,
			{ name: 'AES-GCM' },
			false,
			['encrypt', 'decrypt']
		);

		console.log('##LOG## - decryptAsymmetricEncryption - ssR', ssR);
		console.log('##LOG## - decryptAsymmetricEncryption - toString(ssR)', toString(ssR));

		console.log('##LOG## - decryptAsymmetricEncryption - ct length', ct.length);
		console.log('##LOG## - decryptAsymmetricEncryption - ct toChar length', toString(ct).length);
		console.log('##LOG## - decryptAsymmetricEncryption - ct.ToString():', toString(ct));
		console.log('##LOG## - decryptAsymmetricEncryption - ct BASE64:', Base64.encode(ct));

		const decryptedMessage = await decryptMsgWithSymmetricKey(symmetricKey, iv, data);
		console.log('##LOG## - decryptAsymmetricEncryption - decryptedMessage:', decryptedMessage);

		let objData=toString(decryptedMessage);
		console.log('##LOG## - decryptAsymmetricEncryption - objData:', objData);
		let decryptedValue = objData;
	
		console.log('##LOG## - decryptAsymmetricEncryption - decryptedValue:', decryptedValue);

		resolve(toArrayBuffer(decryptedValue));
	  });

	const result = await decrypted;
	var decryptedResult = EJSON.parse(new TextDecoder('UTF-8').decode(new Uint8Array(result)));

	console.log('##LOG## - decryptAsymmetricEncryption - decryptedResult', result);

	var logObject = {
		eventCount: eventCount++,
		eventName: 'decryptAsymmetricEncryption',
		timestamp: Date.now(),
		dateTime: new Date().toLocaleString('pt-BR'),
		key: key,
		data: data,
		decryptedResult: decryptedResult
	};
	console.log(logObject);
	console.log(JSON.stringify(logObject));

	return decrypted;
}

export async function exportKey_asymmetric(key: any) {
	console.log('##LOG## - exportJWKKey_asymmetric');
	console.log('##LOG## - exportJWKKey_asymmetric - Key:', key);

	let keyExported = new Promise(function(resolve, reject) {
		let keyExported = key;
		console.log('##LOG## - exportJWKKey_asymmetric - keyExported:', keyExported);
		resolve(keyExported);
	  });

	return keyExported;
}

async function encryptMsgWithSymmetricKey(key, message) {
    const iv = crypto.getRandomValues(new Uint8Array(16)); //IV de 16 bytes que é o tamanho do bloco.
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      message
    );

    return { iv, encryptedData: new Uint8Array(encrypted) };
}

async function decryptMsgWithSymmetricKey(key, iv, encryptedData) {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      encryptedData
    );
	return decrypted;
}

interface IRocketChatE2ECryptography {
    exportKey_asymmetric(key: any):Promise<any>;
	decryptAsymmetricEncryption(key: any, data: any):Promise<ArrayBuffer>;
	encryptAsymmetricEncryption(key: any, data: any):Promise<ArrayBuffer>;
	importAsymmetricEncryptionKey(keyData: any, keyUsages: ReadonlyArray<KeyUsage>):Promise<CryptoKey>;
	generateAsymmetricEncryptionKey(): Promise<CryptoKeyPair>;
	setMyKeys():Promise<void>;
}
