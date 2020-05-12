const cookieParser = require('cookie-parser');
require('dotenv').config({path: 'variables.env'});
const createServer = require('./createServer');
const db = require('./db');
const jwt = require('jsonwebtoken');

const server = createServer();

//Use Express MiddleWare to handle cookies (JWT)
server.express.use(cookieParser());

//decode jwt to verify authenticity and get UserID on each request then append it onto the request
server.express.use((req, res, next) => {
    const { token } = req.cookies;
    
    if(token) {
        const { userId } = jwt.verify(token, process.env.APP_SECRET);
        //put userID on the request for the other steps
        req.userID = userId;
    }
    next();
});

//TODO: Use Express MiddleWare to populate current user
server.express.use(async (req, res, next) => {
    //if they aren't logged in, skip this
    if(!req.userID) return next();

    const user = await db.query.user({
        where: {
            id: req.userID
        }
    }, '{ id, permissions, email, firstname, lastname}');
    
    req.user = user; 
    next();
});

server.start({
    cors: {
        credentials: true,
        origin: process.env.FRONTEND_URL
    }
}, deets=>{
    console.log(`Server is now running on http://localhost:${deets.port}`)
});