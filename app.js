const express = require('express')
const bodyParser = require('body-parser')
const FormData = require('form-data')
const session = require('express-session')
const fetch = require('node-fetch')
const sqlite3 = require('sqlite3').verbose()

const child_process = require('child_process')
const crypto = require('crypto')

const TIMEOUT = process.env.TIMEOUT || 30
const CHALLENGE_HOST = process.env.CHALLENGE_HOST || '127.0.0.1'
const CHALLENGE_PORT = 30003
const CHALLENGE_CONTAINER = 'ubuntu:latest'
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '0x4AAAAAAAAAAAAAAAAAAAAA'
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '0x4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

function createInstanceId() {
    return crypto.randomUUID()
}

function createToken() {
    return crypto.randomInt(2 ** 47, 2 ** 48).toString(36)
}

function checkDuplicateId(db, instanceId) {
    const sql = "SELECT * FROM instances WHERE id = ?"
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

function storeInstanceInfo(db, instanceId, port, token) {
    const sql = "INSERT INTO instances VALUES (?, ?, ?)"
    return new Promise((resolve, reject) => {
        db.all(sql, [instanceId, port, token], (err, row) => {
            if (err) {
                reject(err)
            }
            resolve(true)
        })
    })
}

function deleteInstanceInfo(db, instanceId) {
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
    const sql = "SELECT * FROM instances WHERE id = ?"
    return new Promise((resolve, reject) => {
        db.get(sql, [instanceId], (err, row) => {
            if (err) {
                reject(err)
            }
            resolve({ token: row.token, port: row.port })
        })
    })
}

function getRandomPort() {
    let min_port = 49152, max_port = 65535
    return Math.floor(Math.random() * (max_port - min_port + 1) + min_port)
}

function spawnInstance(instanceId, port) {
    return new Promise((resolve, reject) => {
        const command = `docker run --name ${instanceId} -d -e TIMEOUT=${TIMEOUT} -p ${port}:${CHALLENGE_PORT} ${CHALLENGE_CONTAINER}`
        child_process.exec(command, (err) => {
            if (err) {
                reject(err)
            }
            resolve(true)
        })
    })
}

function removeInstance(instanceId, port) {
    return new Promise((resolve, reject) => {
        const command = `docker stop ${instanceId} && docker rm ${instanceId}`
        child_process.exec(command, (err) => {
            if (err) {
                reject(err)
            }
            resolve(true)
        })
    })
}

function setAutoDestroyInstance(db, session, instanceId) {
    setTimeout(() => {
        session.destroy()
        return deleteInstanceInfo(db, instanceId)
    }, TIMEOUT * 60 * 1000)
}

const db = new sqlite3.Database('instances.db')
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS instances (id TEXT PRIMARY KEY, port INTEGER, token TEXT)')

    const app = express()
    app.set('view engine', 'ejs')
    app.use(bodyParser.urlencoded({ extended: false }))
    app.use(session({
        secret: crypto.randomBytes(20).toString('hex'),
        resave: true,
        saveUninitialized: false
    }))

    app.use(express.static('public'))

    app.get('/', (req, res) => {
        if (req.session.instanceId) {
            return res.redirect('/info')
        }
        return res.render('index', { title: 'The Umi', turnstileSitekey: TURNSTILE_SITE_KEY })
    })
    app.get('/info', async (req, res) => {
        const instanceId = req.session.instanceId
        const expiredAt = req.session.expiredAt
        if (!instanceId || !expiredAt) {
            return res.redirect('/')
        }
        try {
            const { token, port } = await getInfoFromInstance(db, instanceId)
            return res.render('info', { title: 'The Umi', host: CHALLENGE_HOST, token, port, expiredAt })
        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            res.status(500).send(message)
        }
    })

    app.post('/delete', (req, res) => {
        const instanceId = req.session.instanceId
        if (!instanceId) {
            return res.redirect('/')
        }

        try {
            removeInstance(instanceId)
            req.session.destroy()
            res.redirect('/')
        } catch (err) {
            const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
            res.status(500).send(message)
        }
    })

    app.post('/create', async (req, res) => {
        const turnstileResponse = req.body['cf-turnstile-response']
        let formData = new FormData()
        formData.append('secret', TURNSTILE_SECRET_KEY)
        formData.append('response', turnstileResponse)
        const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
        const result = await fetch(url, {
            body: formData,
            method: 'POST',
        })
        const outcome = await result.json()
        if (outcome.success) {
            try {
                let instanceId = createInstanceId()
                while (await checkDuplicateId(db, instanceId)) {
                    instanceId = createInstanceId()
                }
                const port = getRandomPort()
                const token = createToken()
                storeInstanceInfo(db, instanceId, port, token)
                spawnInstance(instanceId, port)
                setAutoDestroyInstance(db, req.session, instanceId)

                req.session.instanceId = instanceId
                req.session.expiredAt = new Date(Date.now() + TIMEOUT * 60 * 1000).toLocaleString('en-us')
                return res.redirect('/info')
            } catch (err) {
                const message = `<b>Fatal error:</b><br><pre>${err}</pre><br>Please report this message to the challenge author`
                res.status(500).send(message)
            }
        } else {
            const message = `<b>Error: invalid captcha:</b><br><pre>${outcome['error-codes']}</pre>`
            res.status(404).send(message)
        }
    })
    app.listen(CHALLENGE_PORT)
})
