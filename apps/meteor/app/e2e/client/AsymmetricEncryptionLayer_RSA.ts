var eventCount:number=0;
const name='RSA-OAEP';
const hashName = 'SHA-256';
const RSAKeyModulusLength=2048;

var db_public_key:any;
var db_private_key:any;

import
{
	toString
}
from './helper';

import EJSON from 'ejson';

export async function setMyKeys(privateKey:any, publicKey:any) {
	console.log('##LOG## - setMyKeys');

	if(privateKey && publicKey) {
		db_private_key=privateKey;
		db_public_key=publicKey;

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

	var key = crypto.subtle.generateKey(
		{
			name: name,
			modulusLength: RSAKeyModulusLength,
			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
			hash: { name: hashName},
		},
		true,
		['encrypt', 'decrypt'],
	);

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

	var importKey = crypto.subtle.importKey(
		'jwk' as any,
		keyData,
		{
			name: 'RSA-OAEP',
			modulusLength: RSAKeyModulusLength,
			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
			hash: { name: 'SHA-256' },
		} as any,
		true,
		keyUsages,
	);

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

	var encrypted = crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data);

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

	var decrypted = crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, data);

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

	return crypto.subtle.exportKey('jwk', key);
}

interface IRocketChatE2ECryptography {
    exportKey_asymmetric(key: any):Promise<any>;
	decryptAsymmetricEncryption(key: any, data: any):Promise<ArrayBuffer>;
	encryptAsymmetricEncryption(key: any, data: any):Promise<ArrayBuffer>;
	importAsymmetricEncryptionKey(keyData: any, keyUsages: ReadonlyArray<KeyUsage>):Promise<CryptoKey>;
	generateAsymmetricEncryptionKey(): Promise<CryptoKeyPair>;
	setMyKeys():Promise<void>;
}
