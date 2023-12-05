import { Encryption, EncryptionTimeoutError, OEncryption } from '../src';

async function sleep(ms: number) {
    return await new Promise<void>(resolve => setTimeout(() => resolve(), ms));
}

async function test(opt: OEncryption) {
    console.log('test ---------------------------------', JSON.stringify(opt))
    let t1 = new Encryption(opt);

    {
        let val = "sain uu. ҮШз";
        let t = t1.encrypt(val);
        // console.log('t', t)

        let v = t1.decript(t);
        // console.log('v', v)

        if (val === v) {
            console.log("success encrypt & decrypt", t, v)
        } else {
            throw new Error("not wokring encrypt & decrypt")
        }
    }

    {
        let val = { a: 1, b: 2 };
        let t = t1.encryptObj(val);
        let v = t1.decryptObj<{ a: number, b: number }>(t);

        if (v && v.a === val.a && v.b === val.b) {
            console.log("success encryptObj & decryptObj", t, v)
        } else {
            throw new Error("not wokring encryptObj & decryptObj")
        }
    }

    {
        let val = { a: 1, b: 2 };
        let t = t1.encryptToken(val, 500);
        await sleep(300)
        let v = t1.decryptToken<{ a: number, b: number }>(t);

        if (v && v.a === val.a && v.b === val.b) {
            console.log("success encryptToken & decryptToken", t, v)
        } else {
            throw new Error("not wokring encryptToken & decryptToken")
        }
    }


    {
        let val = { a: 1, b: 2 };
        let t = t1.encryptToken(val, 500);
        await sleep(1000);
        try {
            let v = t1.decryptToken<{ a: number, b: number }>(t);
            throw new Error("not wokring timeout 1 encryptToken & decryptToken")
        } catch (error) {
            if (error instanceof EncryptionTimeoutError) {
                return console.log("success timeout decryptToken & decryptToken", t);
            }
            throw new Error("not wokring timeout2 encryptToken & decryptToken")
        }

    }

}

async function runt() {
    try {
        await test({ pass: '123', saltSize: 64, format: 'hex' })
        await test({ pass: '123', saltSize: 16, format: 'base64' })
        await test({ pass: 'sdfs5df4s5df54s5df5sdfs', saltSize: 48, format: 'hex' })
        await test({ pass: '12', keySize : 512, iterations : 1000 })
    } catch (error) {
        console.error(error)
    }
}


runt()





