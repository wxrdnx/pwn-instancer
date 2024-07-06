const express = require('express')
const bodyParser = require('body-parser')
const FormData = require('form-data')
const session = require('express-session')
const fetch = require('node-fetch')
const sqlite3 = require('sqlite3').verbose()

const child_process = require('child_process')
const crypto = require('crypto')

const TIMEOUT_MINUTE = process.env.TIMEOUT_MINUTE || 30
const WAIT_SPAWN_MINUTE = process.env.WAIT_SPAWN_MINUTE || 1
const CHALLENGE_TITLE = process.env.CHALLENGE_TITLE || 'Seccomp Hell'
const CHALLENGE_HOST = process.env.CHALLENGE_HOST || '127.0.0.1'
const CHALLENGE_PORT = process.env.CHALLENGE_PORT || 30000
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '0x4AAAAAAAJvhe911CZyTjmP'
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '0x4AAAAAAAJvhZ4MTsHE0nw7hB6kPD0PQvs'
const SCOREBOARD_URL = process.env.SCOREBOARD_URL || 'https://scoreboardbeta.hitconctf.com'

async function getInstanceId(req, token) {
    const url = SCOREBOARD_URL + '/team/token_auth?token=' + token
    const test = await fetch(url, {
        method: 'GET',
    })
    const result = await test.json()
    return result['id'] || null
}

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
    const sql = "INSERT INTO instances VALUES (?, ?, ?, ?, ?, ?)"
    return new Promise((resolve, reject) => {
        db.all(sql, [instanceId, port, pid, expiredAt, 0, 0], (err, row) => {
            if (err) {
                reject(err)
            }
            resolve(true)
        })
    })
}

function setInstanceSpawned(db, instanceId) {
    const sql = "UPDATE instances SET spawned = 1 WHERE id = (?)"
    return new Promise((resolve, reject) => {
        db.all(sql, [instanceId], (err, row) => {
            if (err) {
                reject(err)
            }
            resolve(true)
        })
    })
}

function getInstanceSpawned(db, instanceId) {
    const sql = "SELECT spawned FROM instances WHERE id = (?)"
    return new Promise((resolve, reject) => {
        db.get(sql, [instanceId], (err, row) => {
            if (err) {
                reject(err)
            }
            if (row) {
                resolve(row.spawned === 0 ? false : true)
            }
            resolve(null)
        })
    })
}

function incrementInstanceWaited(db, instanceId, waited) {
    const sql = "UPDATE instances SET waited = waited + 1 WHERE id = (?)"
    return new Promise((resolve, reject) => {
        db.all(sql, [instanceId], (err, row) => {
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
            resolve({ port: row.port, pid: row.pid, expiredAt: row.expiredAt, waited: row.waited })
        })
    })
}

async function waitForInstanceToSpawn(db, instanceId, waitSec) {
    let { waited } = await getInfoFromInstance(db, instanceId)
    let countdown = setInterval(async () => {
        waited++
        incrementInstanceWaited(db, instanceId)
        if (waited >= waitSec) {
            clearInterval(countdown)
            await setInstanceSpawned(db, instanceId)
        }
    }, 1000);
}

function getRandomPort() {
    //let minPort = 49152, maxPort = 65535
    let minPort = 49000, maxPort = 50000
    return Math.floor(Math.random() * (maxPort - minPort + 1) + minPort)
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
        const subprocess = child_process.execFile(command, args, (err) => {
            if (err) {
                reject(err)
            }
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

function setAutoDestroyInstance(db, req, instanceId, waitSec) {
    setTimeout(async () => {
        req.session.destroy()
        await deleteInstanceFromId(db, instanceId)
    }, TIMEOUT_MINUTE * 60 * 1000)
}

function getDeltaDisplay(delta) {
    const hours = Math.floor(delta / (60 * 60)).toString().padStart(2, '0')
    const minutes = Math.floor((delta / 60) % 60).toString().padStart(2, '0')
    const seconds = Math.floor(delta % 60).toString().padStart(2, '0')
    return `${hours}:${minutes}:${seconds}`
}

//function sleep(sec) {
    //return new Promise(resolve => setTimeout(resolve, sec * 1000))
//}

const db = new sqlite3.Database('instances.db')
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS instances (
            id TEXT PRIMARY KEY,
            port INTEGER,
            pid INTEGER,
            expiredAt INTEGER,
            spawned INTEGER,
            waited INTEGER
        )
    `)

    const app = express()
    app.set('view engine', 'ejs')
    app.set('trust proxy', true) // i know you can modify X-Forwarded-For with ease but whatever
    app.use(bodyParser.urlencoded({ extended: false }))
    app.use(session({
        secret: crypto.randomBytes(20).toString('hex'),
        resave: true,
        saveUninitialized: false
    }))

    app.use(express.static('public'))

    app.get('/', async (req, res) => {
        try {
            if (req.session && req.session.instanceId) {
                const instanceId = req.session.instanceId
                const spawned = await getInstanceSpawned(db, instanceId)
                if (spawned === true) {
                    return res.redirect('/info')
                }
                else if (spawned === false) {
                    return res.redirect('/wait')
                }
                else if (spawned === null) {
                    req.session.destroy()
                    const message = '<b>Error: invalid session</b>'
                    return res.status(401).send(message)
                }
            }
            return res.render('index', { title: CHALLENGE_TITLE, turnstileSitekey: TURNSTILE_SITE_KEY, invalidToken: false })
        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            return res.status(500).send(message)
        }
    })
    app.get('/info', async (req, res) => {
        try {

            if (!req.session || !req.session.instanceId) {
                return res.redirect('/')
            }

            const instanceId = req.session.instanceId

            const spawned = await getInstanceSpawned(db, instanceId)
            if (spawned === false) {
                return res.redirect('/wait')
            } else if (spawned === null) {
                req.session.destroy()
                const message = '<b>Error: invalid session</b>'
                return res.status(401).send(message)
            }

            const { port, expiredAt } = await getInfoFromInstance(db, instanceId)
            const delta = Math.floor(expiredAt - Date.now() / 1000);
            const deltaDisplay = getDeltaDisplay(delta);
            return res.render('info', { title: CHALLENGE_TITLE, host: CHALLENGE_HOST, port: port, countdown: deltaDisplay })
        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            return res.status(500).send(message)
        }
    })

    app.post('/delete', async (req, res) => {
        try {
            if (!req.session || !req.session.instanceId) {
                return res.redirect('/')
            }

            const instanceId = req.session.instanceId

            const spawned = await getInstanceSpawned(db, instanceId)
            if (spawned === null) {
                req.session.destroy()
                const message = '<b>Error: invalid session</b>'
                return res.status(401).send(message)
            }

            const { pid } = await getInfoFromInstance(db, instanceId)
            await deleteInstanceFromId(db, instanceId)
            await killInstance(pid)
            req.session.destroy()
            return res.redirect('/')

        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            return res.status(500).send(message)
        }
    })

    app.post('/create', async (req, res) => {
        try {
            if (req.session && req.session.instanceId) {
                const instanceId = req.session.instanceId
                const spawned = await getInstanceSpawned(db, instanceId)
                if (spawned === true) {
                    return res.redirect('/info')
                }
                else if (spawned === false) {
                    return res.redirect('/wait')
                }
                else if (spawned === null) {
                    req.session.destroy()
                    const message = '<b>Error: invalid session</b>'
                    return res.status(401).send(message)
                }
            }

            if (!req.body || !req.body.token || !req.body['cf-turnstile-response']) {
                const message = `<b>Error: invalid request</b>`
                return res.status(400).send(message)
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

                const token = req.body['token']

                const instanceId = await getInstanceId(req, token)
                if (instanceId === null) {
                    return res.render('index', { title: CHALLENGE_TITLE, turnstileSitekey: TURNSTILE_SITE_KEY, invalidToken: true })
                }

                req.session.instanceId = instanceId

                const dupId = await checkDuplicateId(db, instanceId)
                if (dupId) {
                    return res.redirect('/info')
                }

                const port = getRandomPort()
                const pid = await spawnInstance(instanceId, port)
                const expiredAt = Math.floor(Date.now() / 1000 + (WAIT_SPAWN_MINUTE + TIMEOUT_MINUTE) * 60)
                await storeInstanceInfo(db, instanceId, port, pid, expiredAt)
                setAutoDestroyInstance(db, req, instanceId, (WAIT_SPAWN_MINUTE + TIMEOUT_MINUTE) * 60)
                waitForInstanceToSpawn(db, instanceId, WAIT_SPAWN_MINUTE * 60)

                //req.session.expiredAt = new Date(Date.now() + TIMEOUT_MINUTE * 60 * 1000).toLocaleString('en-us', { timeZone: 'UTC' })
                return res.redirect('/wait')
            } else {
                const message = `<b>Error: invalid captcha:</b><br><pre>${turnstileResult['error-codes']}</pre>`
                return res.status(404).send(message)
            }
        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            return res.status(500).send(message)
        }
    })
    app.get('/wait', async (req, res) => {
        try {
            if (!req.session || !req.session.instanceId) {
                return res.redirect('/')
            }

            const instanceId = req.session.instanceId

            const spawned = await getInstanceSpawned(db, instanceId)
            if (spawned === true) {
                return res.redirect('/info')
            }
            else if (spawned === null) {
                req.session.destroy()
                const message = '<b>Error: invalid session</b>'
                return res.status(401).send(message)
            }

            const { waited } = await getInfoFromInstance(db, instanceId)
            return res.render('wait', { title: CHALLENGE_TITLE, waited: waited })
        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            return res.status(500).send(message)
        }
    })
    app.listen(CHALLENGE_PORT)
})
