const express = require('express')
const bodyParser = require('body-parser')
const FormData = require('form-data')
//const session = require('express-session')
const fetch = require('node-fetch')
const sqlite3 = require('sqlite3').verbose()

const child_process = require('child_process')
const crypto = require('crypto')

const TIMEOUT = process.env.TIMEOUT || 30
const CHALLENGE_TITLE = process.env.CHALLENGE_TITLE || 'Seccomp Hell'
const CHALLENGE_HOST = process.env.CHALLENGE_HOST || '127.0.0.1'
const CHALLENGE_PORT = process.env.CHALLENGE_PORT || 30003
//const CHALLENGE_CONTAINER = 'ubuntu:latest'
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '0x4AAAAAAAJvhe911CZyTjmP'
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '0x4AAAAAAAJvhZ4MTsHE0nw7hB6kPD0PQvs'

//function createInstanceId() {
    //return crypto.randomUUID()
//}

function getInstaceId(req) {
    return req.ip
}

//function createToken() {
    //return crypto.randomInt(2 ** 47, 2 ** 48).toString(36)
//}

function checkDuplicateId(db, instanceId) {
    const sql = "SELECT * FROM instances WHERE id = (?)"
    return new Promise((resolve, reject) => {
        db.get(sql, [instanceId], (err, row) => {
            if (err) {
                reject(err)
            }
            if (row) {
                resolve(true)
            } else {
                resolve(false)
            }
        })
    })
}

function storeInstanceInfo(db, instanceId, port, pid, expiredAt) {
    const sql = "INSERT INTO instances VALUES (?, ?, ?, ?)"
    return new Promise((resolve, reject) => {
        db.all(sql, [instanceId, port, pid, expiredAt], (err, row) => {
            if (err) {
                reject(err)
            }
            resolve(true)
        })
    })
}

function deleteInstanceFromId(db, instanceId) {
    const sql = "DELETE FROM instances WHERE id = (?)"
    return new Promise((resolve, reject) => {
        db.all(sql, [instanceId], (err, row) => {
            if (err) {
                reject(err)
            }
            resolve(true)
        })
    })
}

function getInfoFromInstance(db, instanceId) {
    const sql = "SELECT * FROM instances WHERE id = (?)"
    return new Promise((resolve, reject) => {
        db.get(sql, [instanceId], (err, row) => {
            if (err) {
                reject(err)
            }
            resolve({ port: row.port, pid: row.pid, expiredAt: row.expiredAt })
        })
    })
}

function getRandomPort() {
    let min_port = 49152, max_port = 65535
    return Math.floor(Math.random() * (max_port - min_port + 1) + min_port)
}

function spawnInstance(instanceId, port) {
    return new Promise((resolve, reject) => {
        const command = `qemu-system-x86_64`
        const args = [
            '-cpu', 'qemu64,+smap',
            '-m', '4096M',
            '-kernel', 'bzImage',
            '-initrd', 'initramfs.cpio.gz',
            '-append', '"console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on"',
            '-monitor', '/dev/null',
            '-nographic',
            '-netdev', `user,id=net0,hostfwd=tcp::${port}-:22222`,
            '-device', 'e1000,netdev=net0',
            '-no-reboot',
        ]
        const subprocess = child_process.spawn(command, args);
        subprocess.on('error', (err) => {
            reject(false)
        });
        resolve(subprocess.pid)
    })
}

function killInstance(pid) {
    return new Promise((resolve, reject) => {
        const command = `kill -2 ${pid}`
        const subprocess = child_process.exec(command, (err) => {
            if (err) {
                reject(err)
            }
        })
        resolve(true)
    })
}

//function deleteInstanceFromPort(instanceId, port) {
    //return new Promise((resolve, reject) => {
        //const command = `kill -2 $(ss -tlpn | grep '0.0.0.0:${port}' | sed 's/.*pid=\\(.*\\),.*/\\1/')`
        //child_process.exec(command, (err) => {
            //if (err) {
                //reject(err)
            //}
            //resolve(true)
        //})
    //})
//}

function deleteInstanceFromPid(db, instanceId, pid) {
    const sql = "DELETE FROM instances WHERE pid = (?)"
    return new Promise((resolve, reject) => {
        db.all(sql, [pid], (err, row) => {
            if (err) {
                reject(err)
            }
        })
        resolve(true)
    })
}

//function setAutoDestroyInstance(db, session, instanceId) {
    //setTimeout(async () => {
        //session.destroy()
        //await deleteInstanceFromId(db, instanceId)
    //}, TIMEOUT * 60 * 1000)
//}

function setAutoDestroyInstance(db, instanceId) {
    setTimeout(async () => {
        await deleteInstanceFromId(db, instanceId)
    }, TIMEOUT * 60 * 1000)
}

function getDeltaDisplay(delta) {
    const hours = Math.floor((delta % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)).toString().padStart(2, '0');
    const minutes = Math.floor((delta % (1000 * 60 * 60)) / (1000 * 60)).toString().padStart(2, '0');
    const seconds = Math.floor((delta % (1000 * 60)) / 1000).toString().padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
}

const db = new sqlite3.Database('instances.db')
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS instances (id TEXT PRIMARY KEY, port INTEGER, pid INTEGER, expiredAt INTEGER)')

    const app = express()
    app.set('view engine', 'ejs')
    app.set('trust proxy', true) // i know you can modify X-Forwarded-For with ease but whatever
    app.use(bodyParser.urlencoded({ extended: false }))
    //app.use(session({
        //secret: crypto.randomBytes(20).toString('hex'),
        //resave: true,
        //saveUninitialized: false
    //}))

    app.use(express.static('public'))

    app.get('/', async (req, res) => {
        //if (req.session.instanceId) {
            //return res.redirect('/info')
        //}
        const instanceId = getInstaceId(req)
        const dupId = await checkDuplicateId(db, instanceId)
        if (dupId) {
            return res.redirect('/info')
        }
        return res.render('index', { title: CHALLENGE_TITLE, turnstileSitekey: TURNSTILE_SITE_KEY })
    })
    app.get('/info', async (req, res) => {
        //const instanceId = req.session.instanceId
        //const expiredAt = req.session.expiredAt
        //if (!instanceId || !expiredAt) {
            //return res.redirect('/')
        //}
        const instanceId = getInstaceId(req)
        const dupId = await checkDuplicateId(db, instanceId)
        if (!dupId) {
            return res.redirect('/')
        }

        try {
            const { port, expiredAt } = await getInfoFromInstance(db, instanceId)
            const delta = expiredAt - Date.now();
            const deltaDisplay = getDeltaDisplay(delta);
            return res.render('info', { title: CHALLENGE_TITLE, host: CHALLENGE_HOST, port: port, countdown: deltaDisplay })
        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            res.status(500).send(message)
        }
    })

    app.post('/delete', async (req, res) => {
        //const instanceId = req.session.instanceId
        const instanceId = getInstaceId(req)
        const dupId = await checkDuplicateId(db, instanceId)
        if (!dupId) {
            return res.redirect('/')
        }

        try {
            const { pid } = await getInfoFromInstance(db, instanceId)
            await deleteInstanceFromId(db, instanceId)
            await killInstance(pid)
            //req.session.destroy()
            res.redirect('/')
        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            res.status(500).send(message)
        }
    })

    app.post('/create', async (req, res) => {
        //const instanceId = req.session.instanceId
        const instanceId = getInstaceId(req)
        const dupIp = await checkDuplicateId(db, instanceId)
        if (dupIp) {
            return res.redirect('/info')
        }

        const turnstileResponse = req.body['cf-turnstile-response']
        let formData = new FormData()
        formData.append('secret', TURNSTILE_SECRET_KEY)
        formData.append('response', turnstileResponse)
        const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
        const result = await fetch(url, {
            body: formData,
            method: 'POST',
        })
        const turnstileResult = await result.json()
        if (turnstileResult.success) {
            try {
                //let instanceId = createInstanceId()
                //while (await checkDuplicateId(db, instanceId)) {
                //    instanceId = createInstanceId()
                //}
                const port = getRandomPort()
                const pid = await spawnInstance(instanceId, port)
                const expiredAt = Date.now() + TIMEOUT * 60 * 1000
                await storeInstanceInfo(db, instanceId, port, pid, expiredAt)
                setAutoDestroyInstance(db, req.session, instanceId)

                //req.session.instanceId = instanceId
                //req.session.expiredAt = new Date(Date.now() + TIMEOUT * 60 * 1000).toLocaleString('en-us', { timeZone: 'UTC' })
                return res.redirect('/info')
            } catch (err) {
                const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
                res.status(500).send(message)
            }
        } else {
            const message = `<b>Error: invalid captcha:</b><br><pre>${turnstileResult['error-codes']}</pre>`
            res.status(404).send(message)
        }
    })
    app.listen(CHALLENGE_PORT)
})
