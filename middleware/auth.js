const jwt = require('jsonwebtoken')
const connectToRedis = require('../config/redisconnection');

module.exports =async  function auth(req,res,next){
       let authheader = req.headers.Authorization || req.headers.authorization
       if (authheader && authheader.startsWith("Bearer")){
        token = authheader.split(" ")[1];
        try {
            const client = await connectToRedis();
            await client.connect();
        
            // Check if the token is blacklisted
            const isBlacklisted = await client.get(token);
            if (isBlacklisted) {
              return res.status(401).json({ message: 'Token is blacklisted, please log in again' });
            }
        
            const verified = jwt.verify(token, process.env.JWT_SECRET);
            req.user = verified;
            next();
          } catch (error) {
            res.status(400).json({ message: 'Invalid Token' });
          }finally {
            client.disconnect();
        }
        
    }
}