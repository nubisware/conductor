const OAuth2Strategy = require('passport-oauth2');

/* @type IAuthentication */
const OAuth2Authentication = {

	getStrategy(options) {
        try {
            console.log(options.strategySettings.authorizationURL);
            console.log(options.strategySettings.tokenURL);
            console.log(options.strategySettings.clientID);
            console.log(options.strategySettings.clientSecret);
            console.log(options.strategySettings.callbackURL);
        return new OAuth2Strategy(
            {
                authorizationURL: options.strategySettings.authorizationURL,
                tokenURL: options.strategySettings.tokenURL,
                clientID: options.strategySettings.clientID,
                clientSecret: options.strategySettings.clientSecret,
                callbackURL: options.strategySettings.callbackURL
            },
            function(accessToken, refreshToken, profile, cb) {
                try {
		    console.log("In callback handler");
		    let buff = new Buffer(accessToken.split(".")[1], 'base64');
		    let at = JSON.parse(buff.toString('ascii'));
		    //console.log("Access token ", at);
                    //console.log("Refresh token ", refreshToken);
                    //console.log("id_token "+JSON.stringify(profile));
                    if(at && at.resource_access && at.resource_access['conductor-ui'].roles.length > 0){
		      console.log("Preparing user ",at.preferred_username);
		      return cb(null, {
                        name: at.preferred_username,
                        displayName: at.name,
                        email: at.email,
			refresh_token: refreshToken,
                        roles: at.resource_access['conductor-ui'].roles
                      })
		   }else{
		     cb(null, false, { message : "Unable to log in. Invalid token or unsufficient roles"});
		   }
                } catch (e) {
                    console.log(e)
                    try {
                        cb(null, false, e);
                    } catch (cbe) {
                        console.log(cbe)
                    }
                }
            }
        )
        } catch (err) {
            console.log(err)
        }
	},

	getDefaultCookieSecret(options) {
           console.log("Accessing default cookie secret",options.cookieSecret)
	   return options.cookieSecret;
	},

	getCookieValueFromUser(req, user, options) {
	   console.log("Transforming user into cookie", user)
	   return user;
	}
}

module.exports = OAuth2Authentication;
