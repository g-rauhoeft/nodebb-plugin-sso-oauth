'use strict';

(function (module) {
	const OAuth2Strategy = require('passport-oauth2'),
		util = require('util');

	function Strategy(options, verify) {
		options = options || {};
		options.realm = options.realm || 'master';
		options.authorizationURL = options.authorizationURL || `auth/realms/${options.realm}/protocol/openid-connect/auth`;
		options.tokenURL = options.tokenURL || `auth/realms/${options.realm}/protocol/openid-connect/token`;
		options.logoutURL = options.logoutURL || `auth/realms/${options.realm}/protocol/openid-connect/logout`;
		options.clientID = options.clientID || 'account';
		options.callbackURL = options.callbackURL || '/auth/keycloak/callback';
		options.scopeSeparator = options.scopeSeparator || ',';
		options.customHeaders = options.customHeaders || {};
		options.passReqToCallback = options.passReqToCallback || true;

		if (!options.customHeaders['User-Agent']) {
			options.customHeaders['User-Agent'] = options.userAgent || 'passport-keycloak';
		}

		OAuth2Strategy.call(this, options, verify);
		this.name = 'keycloak';
		this._userProfileURL = options.userProfileURL || `auth/realms/${options.realm}/protocol/openid-connect/userinfo`;
		this._oauth2.useAuthorizationHeaderforGET(true);
	}

	util.inherits(Strategy, OAuth2Strategy);

	Strategy.prototype.userProfile = function (accessToken, done) {
		this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
			var json;

			if (err) {
				if (err.data) {
					try {
						json = JSON.parse(err.data);
					} catch (_) {}
				}

				if (json && json.message) {
					return done(json.message);
				}
				return done('Failed to fetch user profile', err);
			}

			try {
				json = JSON.parse(body);
			} catch (ex) {
				return done('Failed to parse user profile', ex);
			}

			var profile = json;
			profile.provider = 'keycloak';

			done(null, profile);
		});
	}

	/*
		Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
		hook up NodeBB with your existing OAuth endpoint.

		Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
				or "oauth2" section needs to be filled, depending on what you set "type" to.

		Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

		Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
				a format accepted by NodeBB. Instructions are provided there. (Line 146)

		Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
	*/

	const User = require.main.require('./src/user');
	const Groups = require.main.require('./src/groups');
	const db = require.main.require('./src/database');
	const authenticationController = require.main.require('./src/controllers/authentication');

	const async = require('async');

	const passport = module.parent.require('passport');
	const nconf = module.parent.require('nconf');
	const winston = module.parent.require('winston');

	const constants = Object.freeze({
		name: 'keycloak',
		oauth2: {
			authorizationURL: process.env.NODEBB_AUTHORIZATION_URL,
			tokenURL: process.env.NODEBB_TOKEN_URL,
			clientID: process.env.NODEBB_CLIENT_ID,
			clientSecret: process.env.NODEBB_CLIENT_SECRET,
			realm: process.env.NODEBB_REALM,
			callbackURL: process.env.NODEBB_CALLBACK_URL,
			userProfileURL: process.env.NODEBB_PROFILE_URL,
			passReqToCallback: true
		}
	});

	const OAuth = {};
	let configOk = false;

	if (!constants.name) {
		winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
	} else if (!constants.oauth2.userProfileURL) {
		winston.error('[sso-oauth] User Route required (library.js:31)');
	} else {
		configOk = true;
	}

	OAuth.getStrategy = function (strategies, callback) {
		if (configOk) {

			passport.use(constants.name, new Strategy(constants.oauth2, function (req, accessToken, refreshToken, profile, callback) {
				//console.log("Req:", JSON.stringify(req), "Profile", JSON.stringify(profile));
				OAuth.login({
					oAuthid: profile.sub,
					handle: profile.preferred_username,
					email: profile.email,
					isAdmin: false, //profile.isAdmin,
				}, function (err, user) {
					if (err) {
						return callback(err);
					}
					authenticationController.onSuccessfulLogin(req, user.uid);
					callback(null, user);
				});
			}));

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: '/auth/' + constants.name + '/callback',
				icon: 'fa-check-square',
				scope: (constants.scope || '').split(','),
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.parseUserReturn = function (data, callback) {
		// Alter this section to include whatever data is necessary
		// NodeBB *requires* the following: id, displayName, emails.
		// Everything else is optional.

		// Find out what is available by uncommenting this line:
		console.log(data);

		var profile = {};
		profile.id = data.id;
		profile.displayName = data.name;
		profile.emails = [{
			value: data.email
		}];

		// Do you want to automatically make somebody an admin? This line might help you do that...
		// profile.isAdmin = data.isAdmin ? true : false;

		// Delete or comment out the next TWO (2) lines when you are ready to proceed
		//process.stdout.write('===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n===');
		//return callback(new Error('Congrats! So far so good -- please see server log for details'));

		// eslint-disable-next-line
		callback(null, profile);
	};

	OAuth.login = function (payload, callback) {
		OAuth.getUidByOAuthid(payload.oAuthid, function (err, uid) {
			if (err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid,
				});
			} else {
				// New User
				var success = function (uid) {
					// Save provider-specific information to the user
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					if (payload.isAdmin) {
						Groups.join('administrators', uid, function (err) {
							callback(err, {
								uid: uid,
							});
						});
					} else {
						callback(null, {
							uid: uid,
						});
					}
				};

				User.getUidByEmail(payload.email, function (err, uid) {
					if (err) {
						return callback(err);
					}

					if (!uid) {
						User.create({
							username: payload.handle,
							email: payload.email,
						}, function (err, uid) {
							if (err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	OAuth.getUidByOAuthid = function (oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function (err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function (data, callback) {
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
				function (oAuthIdToDelete, next) {
					db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
				},
		], function (err) {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
	OAuth.whitelistFields = function (params, callback) {
		params.whitelist.push(constants.name + 'Id');
		callback(null, params);
	};

	module.exports = OAuth;
}(module));
