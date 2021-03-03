const jsonServer = require('json-server')
const fs = require('fs')
const _ = require('lodash')
const server = jsonServer.create()
const router = jsonServer.router('db.json')
const middlewares = jsonServer.defaults()
const { check, validationResult } = require('express-validator')

server.use(middlewares)
server.use(jsonServer.bodyParser)

function matchPattern(str, pattern) {
    const escapeRegex = (s) => s.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1");
    return new RegExp("^" + pattern.split("*").map(escapeRegex).join(".*") + "$").test(str);
}

function matchPatterns(str, patterns) {
    for (let pattern of patterns) {
        if (matchPattern(str, pattern)) {
            return true
        }
    }

    return false
}

function getDB() {
    return JSON.parse(fs.readFileSync('db.json', 'utf8'))
}

function writeToDB(data) {
    fs.writeFileSync('db.json', JSON.stringify(data));
}

function getUserByEmail(users, email) {
    return _.find(users, (u) => u.email === email)
}

function getUserByPhone(users, phone) {
    return _.find(users, (u) => u.phone === phone)
}

function getUserByApiToken(users, token) {
    return _.find(users, (u) => u.api_token === token)
}

function isAuthorized(req) {
    if (!req.query.api_token) return false
    return getUserByApiToken(getDB().users, req.query.api_token)
}

function getUniqueApiToken() {
    const users = getDB().users

    const genToken = () => Math.random().toString(36).slice(2)
    let token = genToken()

    while (getUserByApiToken(users, token)) {
        token = genToken()
    }

    return token
}

server.use((req, res, next) => {
    const isGuestRoute = matchPatterns(req.url, [
        '/login',
        '/register'
    ])

    if (isGuestRoute || isAuthorized(req)) {
        req.user = getUserByApiToken(getDB().users, req.query.api_token)
        next()
    } else {
        res.json({
            message: 'Unauthorized'
        }, 401)
    }
})

server.post(
    '/login',
    check('username')
        .notEmpty()
        .trim()
        .withMessage((value, { path }) => {
            return `The ${path} field is required.`
        }),
    check('password')
        .trim()
        .notEmpty()
        .withMessage((value, { path }) => {
            return `The ${path} field is required.`
        }),
    (req, res) => {
        const errors = validationResult(req);
        if (! errors.isEmpty()) {
            return res.status(400).json({ errors: errors.mapped() });
        }

        const db = getDB()
        let user = getUserByEmail(db.users, req.body.username)

        if (!user) {
            user = getUserByPhone(db.users, req.body.username)
        }

        if (!user || (user && user.password !== req.body.password)) {
            return res.status(400).json({
                message: 'These credentials do not match our records.'
            });
        }

        const userIdx = _.findIndex(db.users, (u) => u.email === req.body.email)
        user.api_token = getUniqueApiToken()
        db.users[userIdx] = user

        writeToDB(db)

        res.json({
            message: 'Success',
            data: _.omit(user, 'password')
        })
    }
)

server.post(
    '/register',
    check('name')
        .notEmpty()
        .trim()
        .withMessage((value, { path }) => {
            return `The ${path} field is required.`
        })
        .isLength({ min: 5 })
        .withMessage((value, { path }) => {
            return `The ${path} must be at least 5 characters.`
        }),
    check('email')
        .notEmpty()
        .trim()
        .withMessage((value, { path }) => {
            return `The ${path} field is required.`
        })
        .custom((value, { req }) => {
            const user = getUserByEmail(getDB().users, req.body.email)
            return !user
        })
        .withMessage((value, { path }) => {
            return `The ${path} has been taken.`
        }),
    check('password')
        .trim()
        .notEmpty()
        .withMessage((value, { path }) => {
            return `The ${path} field is required.`
        }),
    check('password_confirmation')
        .trim()
        .notEmpty()
        .withMessage((value, { path }) => {
            return `The ${path} field is required.`
        })
        .custom((value, { req }) => {
            return value === req.body.password
        })
        .withMessage((value, { path }) => {
            return `The password confirmation does not match.`
        }),
    check('phone')
        .notEmpty()
        .trim()
        .withMessage((value, { path }) => {
            return `The ${path} field is required.`
        })
        .isMobilePhone('any')
        .withMessage((value, { path }) => {
            return `The ${path} must be a valid phone number.`
        })
        .customSanitizer(value => {
            return value.replace('+', '')
                .replace(' ', '')
                .replace('-', '')
        })
        .custom((value, { req }) => {
            const user = getUserByPhone(getDB().users, value)
            return !user
        })
        .withMessage((value, { path }) => {
            return `The ${path} has been taken.`
        }),
    (req, res) => {
        const errors = validationResult(req);
        if (! errors.isEmpty()) {
            return res.status(400).json({ errors: errors.mapped() });
        }

        const db = getDB()

        const lastUser = _.first(_.orderBy(
            _.get(db, 'users', []),
            'id',
            'desc'
        ))

        const newUser = {
            id: _.get(lastUser, 'id', 0) + 1,
            name: req.body.name,
            email: req.body.email,
            password: req.body.password,
            phone: req.body.phone
        }

        _.get(db, 'users', []).push(newUser)

        writeToDB(db)

        res.json({
            message: 'Success',
            data: _.omit(newUser, 'password')
        })
    }
)

server.post('/logout', (req, res) => {
    try {
        const db = getDB()

        const user = getUserByEmail(db.users, req.user.email)
        user.api_token = undefined

        writeToDB(db)
    } catch (e) {
        // The email may change on users update, makes not found.
    }

    req.user = undefined

    res.json({}, 204)
})


server.use(router)
server.listen(3000, () => {
    console.log('JSON Server is running')
})
