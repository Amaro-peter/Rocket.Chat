var eventCount:number=0;

var db_public_key:any;
var db_private_key:any;
var myElGamalObj:ElGamal;
const p_elgamal = Utils.parseBigInt('27318743055230173004612147237172739117449351314326023137045745029608063636173225114005045655449483622295672328937894182690431604214833565098735847048393158061799651622041668709431238216781270363890699601150399584515269009329439909063239803901018797765784987443371295118803152462146163822622383891801404302862563821683107857889384921218479510905422683076583558121059632934097021602799906467439967435153071057904340076270150845712137904495580553258684388418069209084524266040248004411516259835700875117564427923200070922848230775789590673384215844056898756890051153472788192506633558804857572850621337805590921798054923');
const g_elgamal = Utils.parseBigInt('26813002784406222584365440781085275538698904483530638195244527396387181022264466638472745982357505873207430472920532380536689393934154592613743911119281424180513966185781789981628908370894715238080439809248254029225517083209407363090415560071856643933754561051884345752774137018467057478006342407368067072692086349905755907427284550621703496316800269577578241373737050413697884289316203297658225623033042601709198366482634143319007496081336922485580643888546189565607146592072117688872734654148907278276954951851329714135660426151579413963268917788948130619511466398929815505997077787637983451239463048803530306908860');

import ElGamal from 'elgamal';
import { Utils, EncryptedValue, BigInt } from 'elgamal';

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
		db_private_key=Utils.parseBigInt(privateKey.toString());
		db_public_key=Utils.parseBigInt(publicKey.toString());

		console.log(privateKey);
		console.log(publicKey);
		console.log(privateKey.toString());
		console.log(publicKey.toString());

		myElGamalObj= new ElGamal(p_elgamal, g_elgamal, publicKey, privateKey);
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
		// Generate private key
		const x_alice = await Utils.getRandomBigIntAsync(
			Utils.BIG_TWO,
			p_elgamal.subtract(BigInt.ONE)
		);
	
		// Generate public key
		const y_alice = g_elgamal.modPow(x_alice, p_elgamal);

		let generatedKeySet = {
			"publicKey": y_alice.toString(),
			"privateKey": x_alice.toString()
		}

		console.log('generateAsymmetricEncryptionKey_generatedKeySet:', generatedKeySet);

		setMyKeys(x_alice, y_alice);

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
		var bobDummy = new ElGamal(p_elgamal, g_elgamal, key, null);

		let pureRawEncrypted=await bobDummy.encryptAsync(toString(data));
		let jsonStringEncrypted = JSON.stringify({a:pureRawEncrypted.a.toString(), b:pureRawEncrypted.b.toString()});

		console.log('encryptAsymmetricEncryption_jsonStringEncrypted', jsonStringEncrypted);

		resolve(toArrayBuffer(jsonStringEncrypted));
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
		let parsedObjData=JSON.parse(toString(data));
		console.log('##LOG## - decryptAsymmetricEncryption - parsedObjData:', parsedObjData);

		let a = new BigInt(parsedObjData.a);
		let b = new BigInt(parsedObjData.b);
		parsedObjData= new EncryptedValue(a, b);
	
		let decryptedValueObj = await myElGamalObj.decryptAsync(parsedObjData);
		console.log('##LOG## - decryptAsymmetricEncryption - decryptedValueObj:', decryptedValueObj);

		let decryptedValue = decryptedValueObj.toString();
	
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

interface IRocketChatE2ECryptography {
    exportKey_asymmetric(key: any):Promise<any>;
	decryptAsymmetricEncryption(key: any, data: any):Promise<ArrayBuffer>;
	encryptAsymmetricEncryption(key: any, data: any):Promise<ArrayBuffer>;
	importAsymmetricEncryptionKey(keyData: any, keyUsages: ReadonlyArray<KeyUsage>):Promise<CryptoKey>;
	generateAsymmetricEncryptionKey(): Promise<CryptoKeyPair>;
	setMyKeys():Promise<void>;
}
