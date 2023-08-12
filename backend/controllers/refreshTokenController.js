const User = require('../model/User');
const jwt = require('jsonwebtoken');

const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);
    const refreshToken = cookies.jwt;
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });

    const foundUser = await User.findOne({ refreshToken }).exec();

    // Detected refresh token reuse!
    if (!foundUser) { 
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) return res.sendStatus(403); // never issued token (just invalid), no worries and just return 403
                
                // if the refresh token would be valid 
                // exec(): execute that call right at the end
                // By calling exec() at the end of a query, you are essentially executing the query and converting the query object into a Promise. This allows you to handle the query's result using await in an async function
                const hackedUser = await User.findOne({ username: decoded.username }).exec() 
                hackedUser.refreshToken = []; // delete all the refresh tokens
                const result = await hackedUser.save();
                console.log(result);
            }
        )
        return res.sendStatus(403); //Forbidden 
    } 

    // delete only the refresh token which is an old one
    const newRefreshTokenArray = foundUser.refreshToken.filter(rt => rt !== refreshToken);

    // evaluate jwt 
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err) {
                // we've received the token, but at the same time the token has expired
                // we found the user it was related to all of that is good
                // but we have an expired token that is being replaced
                // so at this point we need to update our data in the database
                foundUser.refreshToken = [...newRefreshTokenArray];
                const result = await foundUser.save();
            }
            if (err || foundUser.username !== decoded.username) return res.sendStatus(403);

            /* Refresh token was still valid */
            // at this point, we found the user we had a refresh token 
            // but it was an old one
            const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": decoded.username,
                        "roles": roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '10s' }
            );

            const newRefreshToken = jwt.sign(
                { "username": foundUser.username },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: '1d' }
            );
            
            // Saving a new refreshToken with current user
            foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
            const result = await foundUser.save();

             // Creates Secure Cookie with refresh token
            res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });
            res.json({ roles, accessToken })
        }
    );
}

module.exports = { handleRefreshToken }