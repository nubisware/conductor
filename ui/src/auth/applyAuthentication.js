const
  cookieParser = require('cookie-parser'),
  passport = require('passport'),
  bodyParser = require('body-parser'),
  strategies = require('./strategies'),
  accessControlMiddleware = require('./accessControlMiddleware');

const defaultOptions = {
  cookieName: "conductor_ui_auth",
  cookieRoll: true,
  cookie: {
    httpOnly: true,
    sameSite: true,
    maxAge: 20 * 60 * 1000, // 20 minutes
    signed: true
  },
  audit: false,
  indexPath: "/",
  loginPath: "/login",
  logoutPath: "/logout"
};

/**
 * @typedef {Object} ApplyAuthenticationOptions
 * @property strategy {string}
 * @property strategyOptions {Object}
 * @property strategySettings {Object}
 * @property acl {Array<String>}
 * @property [cookieName] {string}
 * @property [cookieSecret] {string}
 * @property [cookieRoll] {boolean}
 * @property [cookie] {Object}
 * @property [audit] {boolean|function}
 * @property [indexPath] {string}
 * @property [loginPath] {string}
 * @property [logoutPath] {string}
 */

/**
 * Adds Passport.js authentication to an Express server
 * @param app
 * @param opt {ApplyAuthenticationOptions}
 */
module.exports = (app, opt) => {

  // extract options (merge with defaults)
  /** @type ApplyAuthenticationOptions */
  const options = Object.assign({}, defaultOptions, opt);
  options.cookie = Object.assign({}, defaultOptions.cookie, opt.cookie);

  // if audit is required and no function was specified, use console
  if (options.audit === true) {
    options.audit = msg => console.log('[Audit] ' + msg);
  }

  // validate authentication strategy
  if (!strategies[options.strategy]) {
    throw new Error(`Authentication strategy ${options.strategy} is not supported!`);
  }
  const authentication = strategies[options.strategy];

  // setup passport and express
  passport.use(authentication.getStrategy(options));
  app.use(cookieParser(options.cookieSecret || authentication.getDefaultCookieSecret(options), options.cookie));
  app.use(passport.initialize());
  app.use(accessControlMiddleware(options));

  // create authentication endpoints

  if (options.strategy === "oauth2") {
    app.get(options.loginPath, passport.authenticate(options.strategy));
  } else {
    app.post(options.loginPath,
      bodyParser.urlencoded({ extended: false }),
      async (req, res, next) => {
        passport.authenticate(options.strategy, { session : false }, (err, user, info) => {
            console.log("Inside login path POST", err, res, next)
            if (err) {
              return next(err);
            }
            if (!user) {
              res.redirect(options.loginPath + '?error=' + encodeURIComponent(info.message));
              return next();
            }
            if (options.audit) {
                options.audit(`User ${req.body.username} logged in`);
            }
            const cookieValue = authentication.getCookieValueFromUser(req, user, options);
            res.cookie(options.cookieName, JSON.stringify(cookieValue), options.cookie);
            res.redirect(options.indexPath);
            next();
        })(req, res, next);
      }
    );
  }

  passport.serializeUser(function(user, done) {
    done(null, user);
  });

  passport.deserializeUser(function(user, done) {
    done(null, user);
  }); 

  app.get(options.loginPath + "/callback",
    passport.authenticate(options.strategy),
    function (req, res, next) {
      //console.log("Authentication has worked now proceed with roles...");
      if (options && options.strategySettings && options.strategySettings.roles) {
        //console.log(" options roles " + JSON.stringify(options.strategySettings.roles));
        //console.log(" options user roles " + JSON.stringify(req.user.roles));
        for (var i = 0; i < options.strategySettings.roles.length; i++) {
          if (req.user.roles && req.user.roles.indexOf(options.strategySettings.roles[i]) >= 0) {
            const cookieValue = authentication.getCookieValueFromUser(req, req.user, options);
            res.cookie(options.cookieName, JSON.stringify(cookieValue), options.cookie);
            //console.log("Everything ok in callback... going on")
            return res.send('<html><head><meta http-equiv="refresh" content="0;URL=' + options.indexPath + '" /></head><body></body></html>');
          }
        }
        //console.log("No suitable roles returned");
        res.clearCookie(options.cookieName, options.cookie);
        res.redirect(options.loginPath);
        next();
      }
    }
  );

  app.get(options.logoutPath, (req, res) => {
    if (req.user && options.audit) {
      options.audit(`User ${req.user.name} logged out`);
    }
    res.clearCookie(options.cookieName, options.cookie);
    if (options.strategy === "oauth2") {
      res.sendFile("/public/logged-out.html", { root: '.' });
    }
  });

  if (options.strategy === "oauth2") {
    app.get(options.logoutPath + "/sso", (req, res) => {
      res.redirect(options.strategySettings.logoutURL + "?redirect_uri=" + options.strategySettings.logoutCallbackURL);
    });

    app.get(options.logoutPath + "/callback", (req, res) => {
      res.sendFile("/public/logged-out-sso.html", { root: '.' }); 
    });
  }

  app.get('/api/me', (req, res) => {
    if(req.user){
      res.send({
        user: req.user,
        logoutPath: options.logoutPath
      })
    }
  });
};
