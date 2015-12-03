(function(module) {
	'use strict';
	/* globals require, module */

	var User = module.parent.require('./user'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport'),
  		passportMapmakers = require('passport-mapmakers').Strategy,
  		nconf = module.parent.require('nconf'),
        async = module.parent.require('async');
    
    var constants = Object.freeze({
		'name': "Mapmakers",
		'admin': {
			'route': '/plugins/sso-mapmakers',
			'icon': 'icon-mapmakers'
		}
	});
    
    var Mapmakers = {};
    
	Mapmakers.init = function(data, callback) {
		function render(req, res, next) {
			res.render('admin/plugins/sso-mapmakers', {});
		}

		data.router.get('/admin/plugins/sso-mapmakers', data.middleware.admin.buildHeader, render);
		data.router.get('/api/admin/plugins/sso-mapmakers', render);

		callback();
	};

	Mapmakers.getStrategy = function(strategies, callback) {
		meta.settings.get('sso-mapmakers', function(err, settings) {
			if (!err && settings.id && settings.secret) {
				passport.use(new passportMapmakers({
					clientID: settings.id,
					clientSecret: settings.secret,
					callbackURL: nconf.get('url') + '/auth/mapmakers/callback'
				}, function(accessToken, refreshToken, profile, done) {
					console.log(profile);
					Mapmakers.login(profile.id, profile.displayName, profile.emails[0].value, function(err, user) {
						if (err) {
							return done(err);
						}
						done(null, user);
					});
				}));

				strategies.push({
					name: 'mapmakers',
					url: '/auth/mapmakers',
					callbackURL: '/auth/mapmakers/callback',
					icon: 'icon-mapmakers'
					// scope: 'https://www.mapmakersapis.com/auth/userinfo.profile https://www.mapmakersapis.com/auth/userinfo.email'
				});
			}

			callback(null, strategies);
		});
	};

	Mapmakers.login = function(mapmakersid, handle, email, callback) {
		Mapmakers.getUidByMapmakersId(mapmakersid, function(err, uid) {
			if(err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				var success = function(uid) {
					meta.settings.get('sso-mapmakers', function(err, settings) {
						var autoConfirm = settings && settings['autoconfirm'] === "on" ? 1 : 0;
						User.setUserField(uid, 'email:confirmed', autoConfirm);
						// Save mapmakers-specific information to the user
						User.setUserField(uid, 'mapmakersid', mapmakersid);
						db.setObjectField('mapmakersid:uid', mapmakersid, uid);
										
						callback(null, {
							uid: uid
						});
					});
				};

				User.getUidByEmail(email, function(err, uid) {
					if(err) {
						return callback(err);
					}

					if (!uid) {
						User.create({username: handle, email: email}, function(err, uid) {
							if(err) {
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

	Mapmakers.getUidByMapmakersId = function(mapmakersid, callback) {
		db.getObjectField('mapmakersid:uid', mapmakersid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	Mapmakers.addMenuItem = function(custom_header, callback) {
		custom_header.authentication.push({
			"route": constants.admin.route,
			"icon": constants.admin.icon,
			"name": constants.name
		});

		callback(null, custom_header);
	}

	Mapmakers.deleteUserData = function(uid, callback) {
		async.waterfall([
			async.apply(User.getUserField, uid, 'mapmakersid'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField('mapmakersid:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-mapmakers] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
				return callback(err);
			}
			callback(null, uid);
		});
	};

	module.exports = Mapmakers;
}(module));
