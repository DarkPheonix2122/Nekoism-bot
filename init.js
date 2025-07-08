const express = require("express");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const bodyParser = require("body-parser");
const path = require("path");
const BOT_API = "https://fs-variance-secondary-pipe.trycloudflare.com";
const SHARED_SECRET = "sbhcwiehbfcuhdghvw93281746";
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const axios = require("axios");
axios.get(`${BOT_API}/api/client`,{
	headers: { Authorization: `Bearer ${SHARED_SECRET}` }
});
async function startSite() {
    try{
    const songFavorites = client.songFavorites;

    const SITE_URL = "http://localhost:3000"
    const CLIENT_ID = "1379083377868673064";
    const CLIENT_SECRET = "xiwUz3GPSkhP6R7oeH9s_O_52AohU4kV";
    const CALLBACK_SITE_URL = "http://localhost:3000/callback";
    const CALLBACK_LOGIN_URL = "http://localhost:3000/callback-verify"
    const SESSION_SECRET = "4135231b7f33c6567493mb2a78420fa76";
    const app = express();
    const errorHandler = require('./functions/errorHandler');
    app.set("view engine", "ejs");
    app.set("views", path.join(__dirname, "views"));
    app.use(express.static(path.join(__dirname, "public")));
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(cookieParser());
    app.use(session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false }
    }));

    app.use(passport.initialize());
    app.use(passport.session());

    passport.serializeUser((user, done) => done(null, user));
    passport.deserializeUser((obj, done) => done(null, obj));

    passport.use("discord-login", new DiscordStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        callbackURL: CALLBACK_SITE_URL,
        scope: ["identify", "guilds"]
    }, (accessToken, refreshToken, profile, done) => {
        process.nextTick(() => done(null, profile));
    }));
    passport.use('discord-verify', new DiscordStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        callbackURL: CALLBACK_LOGIN_URL,
        scope: ["identify"],
        state: true
    }, (accessToken, refreshToken, profile, done) => {
        process.nextTick(() => done(null, profile));
    }));
    function ensureAuth(req, res, next) {
        if (req.isAuthenticated()) return next();
        res.redirect("/login");
    }
    function generateRandomPassword(length = 12) {
        return crypto.randomBytes(length).toString("base64").slice(0, length);
    }
    // --- ROUTES ---

    app.get("/", (req, res) => {
        let error = req.query.error
        if(error){
            return errorHandler(error, req, res)
        }
        const totalGuilds = client.guilds.cache.size;
        const totalUsers = client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0);
        res.render("index", { 
            totalGuilds,
            totalUsers,
            user: req.user 
        })
    });
    app.get("/about", (req, res) => {

    })

    app.get("/login", passport.authenticate("discord-login"));
    app.get("/callback", passport.authenticate("discord-login", { failureRedirect: "/" }), (req, res) => res.redirect("/dashboard"));

    app.get("/logout", (req, res) => {
        req.logout(() => res.redirect("/"));
    });

    function getSidebar(user, guilds, active, selectedGuild) {
        return {
            user,
            guilds,
            active,
            selectedGuild
        };
    }
    function requireUserSetup(req, res, next) {
        const userId = req.user.id;
        // Check if userGlobalSettings exists for this user
        const global = client.userGlobalSettings.get(userId);
        // You can add more checks if you want to ensure all required fields are set
        if (!global) {
            return res.redirect(`/setup/user/${userId}`);
        }
        next();
    }
    async function requireGuildSetup(req, res, next) {
        try {
            const guildID = req.params.guildID || req.body.guildID || req.query.guildID;
            if (!guildID) {
                return res.status(400).send("Guild ID is required.");
            }
            const defaultModules = {};
            for (const key of Object.keys(config.modules)) {
                defaultModules[key] = false; // default to false unless setup says otherwise
            }

            // Wait for the settings to load or create default if missing
            const guildSettings = await client.settings.ensure(guildID, {
                prefix: config.prefix,
                lang: "en",
                welcomeChannel: null,
                leaveChannel: null,
                defaultRole: null,
                giveawayChannel: null,
                defaultMusicChannel: null,
                setup: true,
                setupComplete: false,
                modules: defaultModules
            });

            // Check if guild setup is complete or whatever your condition is
            if (!guildSettings.setupComplete) {
                return res.redirect(`/setup/guild/${guildID}`);
            }

            // If everything is fine, proceed
            next();
        } catch (error) {
            res.redirect("/?error="+encodeURIComponent(error.message));
        }
    }
    // Dashboard: show all mutual servers, admin link if owner
    app.get("/dashboard", ensureAuth, requireUserSetup, (req, res) => {
        const userGuilds = req.user.guilds;
        const mutualGuilds = userGuilds.filter(g => client.guilds.cache.has(g.id));
        const totalGuilds = client.guilds.cache.size;
        const totalUsers = client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0);
        const isOwner = config.owners.includes(req.user.id);
        res.render("dashboard", {
            user: req.user,
            guilds: mutualGuilds,
            totalGuilds,
            totalUsers,
            isOwner,
            sidebar: getSidebar(req.user, mutualGuilds, "dashboard")
        });
    });

    // Admin page
    app.get("/admin", ensureAuth, (req, res) => {
        if (!config.owners.includes(req.user.id)) return res.status(403).send("Forbidden");
        const totalGuilds = client.guilds.cache.size;
        const totalUsers = client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0);
        const latency = client.ws.ping;
        const events = client.eventNames().length;
        const commands = client.commands ? client.commands.size : 0;
        res.render("admin", { 
            user: req.user,
            totalGuilds, 
            totalUsers, 
            latency, 
            events, 
            commands,
            sidebar: getSidebar(req.user, req.user.guilds, "admin")
        });
    });
    app.get("/dashboard/user/economy", ensureAuth, async (req, res) => {
        const userId = req.user.id;
        const totalGuilds = client.guilds.cache.size;
        const totalUsers = client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0);
        // Get or create default economy data
        const economyData = await client.economy.get(userId)

        res.render("user-economy", {
            user: req.user,
            economy: economyData,
            totalGuilds,
            totalUsers
        });
    });

    // Settings page: view for all, edit for admins, userSettings for non-admins
    app.get("/dashboard/settings/:guildID", ensureAuth, requireGuildSetup, async (req, res) => {
        const guildID = req.params.guildID;
        const guild = client.guilds.cache.get(guildID);
        if (!guild) return res.send("Bot is not in this server.");

        const channels = guild.channels.cache.filter(c => c.type === 0).map(c => ({ id: c.id, name: c.name }));
        const roles = guild.roles.cache.filter(r => r.name !== "@everyone").map(r => ({ id: r.id, name: r.name }));

        const settingsData = await client.settings.ensure(guildID, {
            prefix: config.prefix,
            lang: "en",
            welcomeChannel: null,
            welcomeMessage: null,
            leaveChannel: null,
            leaveMessage: null,
            defaultRole: null,
            giveawayChannel: null,
            defaultMusicChannel: null,
            setup: true,
            setupComplete: false,
            modules: config.modules
        });
        const moduleKeys = Object.keys(settingsData.modules);

        // Check if user is admin in this guild
        const userGuild = req.user.guilds.find(g => g.id === guildID);
        const isAdmin = userGuild && (userGuild.permissions & 0x8) === 0x8;

        const userGuilds = req.user.guilds;
        const mutualGuilds = userGuilds.filter(g => client.guilds.cache.has(g.id));
        res.render("settings", {
            user: req.user,
            guildID,
            settings: settingsData,
            channels,
            roles,
            moduleKeys,
            isAdmin,
            sidebar: getSidebar(req.user, mutualGuilds, "settings"),
            totalGuilds: client.guilds.cache.size,
            totalUsers: client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0)
        });
    });

    // Save guild settings (admin only)
    app.post("/dashboard/settings/:guildID", ensureAuth, requireGuildSetup, (req, res) => {
        const guildID = req.params.guildID;
        const userGuild = req.user.guilds.find(g => g.id === guildID);
        const isAdmin = userGuild && (userGuild.permissions & 0x8) === 0x8;
        if (!isAdmin) return res.status(403).send("Forbidden");

        let { welcomeChannel, welcomeMessage, leaveChannel, leaveMessage, defaultRole, giveawayChannel, defaultMusicChannel, prefix, modules, verificationPassword, verifiedRole, verificationChannel  } = req.body;
        const currentModules = Object.keys(config.modules);
        if (!modules) modules = [];
        if (!Array.isArray(modules)) modules = [modules];
        const modulesObj = {};
        for (const key of currentModules) {
            modulesObj[key] = modules.includes(key);
        }
        if (req.body.disableTab === 'intro') {
            welcomeChannel = null;
            welcomeMessage = null;
            leaveChannel = null;
            leaveMessage = null;
        }
        if (req.body.disableTab === 'verification') {
            verificationPassword = null;
            verifiedRole = null;
            verificationChannel = null;
        }
        client.settings.set(guildID, {
            ...client.settings.get(guildID),
            welcomeChannel,
            welcomeMessage,
            leaveChannel,
            leaveMessage,
            defaultRole,
            giveawayChannel,
            defaultMusicChannel,
            prefix,
            verifiedRole,
            verificationChannel,
            verificationPassword,
            modules: modulesObj
        });
        if (verifiedRole && verificationChannel) {
            const guild = client.guilds.cache.get(guildID);
            const channel = guild.channels.cache.get(verificationChannel);
            if (channel) {
                channel.send({
                    content: "Click below to verify yourself.",
                    components: [{
                        type: 1,
                        components: [{
                            type: 2,
                            style: 1,
                            label: "Verify Me",
                            custom_id: `verify_start`
                        }]
                    }]
                }).catch(err => {
                    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
                });
            }
        }
        res.redirect(`/dashboard/settings/${guildID}`);
    });

    app.get("/login-verify", (req, res, next) => {
        const guildID = req.query.guildID;
        if (!guildID) return res.status(400).send("Missing guildID.");
        res.cookie("guildID", guildID, { maxAge: 5 * 60 * 1000, httpOnly: true });
        passport.authenticate("discord-verify", {
            scope: ["identify"]
        })(req, res, next);
    });

    app.get("/callback-verify", (req, res, next) => {
        passport.authenticate("discord-verify", (err, user, info) => {
            if (err) {
                return res.redirect("/?error="+encodeURIComponent(err.message));
            }
            if (!user) {
                return res.redirect("/?error="+encodeURIComponent("No user returned: "+info));
            }
            req.logIn(user, (loginErr) => {
                if (loginErr) {
                    return res.redirect("/?error="+encodeURIComponent(loginErr.message));
                }

                const guildID = req.cookies.guildID;
                if (!guildID) {
                    return res.redirect("/?error="+encodeURIComponent("Missing guildID in session"));
                }
                res.redirect(`/verify/${guildID}`);
            });
        })(req, res, next);
    });

    app.get("/verify/:guildID", async (req, res) => {
        const guildID = req.params.guildID;
        if (!req.isAuthenticated || !req.isAuthenticated()) {
            return res.redirect(`/login-verify?guildID=${guildID}`); // Or handle with a custom message
        }
        let userGSettings = await client.userGlobalSettings.get(req.user.id);
        const password = generateRandomPassword();
        if(!userGSettings.password){
            userGSettings.password = password
        }
        await client.userGlobalSettings.set(req.user.id, {
            ...userGSettings,
            password: password
        });
        res.clearCookie("guildID");
        const userID = req.user.id;
        const creationDate = new Date(userID / 4194304 + 1420070400000);
        const ageInDays = Math.floor((Date.now() - creationDate) / (1000 * 60 * 60 * 24));
        const guildName = client.guilds.cache.get(guildID).name;
        try {
            const guild = client.guilds.cache.get(guildID)
            const guildSettings = await client.settings.get(guildID);
            const showPassword = ageInDays >= 10;
            const roleName = guild.roles.cache.get(guildSettings.verifiedRole).name;
            res.send(`
                <h2>Verification for ${guildName ?? "your server"}</h2>
                <p>Your account is ${ageInDays} days old.</p>
                ${showPassword 
                    ? `<p>🔐 Your password: <code>${password}</code>. Use it with <code>!verify ${password}</code> in DMs to get the role "${roleName}".</p>
                    <p1> If you cannot DM the bot, or the bot does not respond to you, try using <code>!verify dm</code> in the guild so the bot can allow messages from you</p1>` 
                    : `<p>❌ Your account is too new to verify. Try again in ${10 - ageInDays} days.</p>`}
            `);
            return req.logout(function (err) {
                if (err) res.redirect(`/?error=${encodeURIComponent(err.message)}`);
            });
        } catch (e) {
            res.redirect(`/?error=${encodeURIComponent(e.message)}`);
            return res.status(500).send("Server error.");
        }
    });

    app.get("/verification", ensureAuth, (req, res) => {
        const totalGuilds = client.guilds.cache.size;
        const totalUsers = client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0);
        const userGlobalSettings = client.userGlobalSettings
        res.render("verification", {
            user: req.user,
            userGlobalSettings,
            totalGuilds, 
            totalUsers,
            sidebar: getSidebar(req.user, req.user.guilds, "verification")
        });
    });

    const multer = require("multer");
    const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB max

    app.post("/verification", upload.single("photo"), async (req, res) => {
        const { dob, "cf-turnstile-response": token } = req.body;
        if (!dob || !token || !req.file) {
            return res.json({ success: false, error: "All fields are required." });
        }

        // Cloudflare Turnstile verification
        const secretKey = "0x4AAAAAABhVtdzv2BC2wE1ZCzwriq0nEdI"; // Replace with your Turnstile secret key
        const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `secret=${secretKey}&response=${token}&remoteip=${req.ip}`
        });
        const verifyData = await verifyRes.json();
        if (!verifyData.success) {
            return res.json({ success: false, error: "Failed robot verification." });
        }
        await client.userGlobalSettings.set(req.user.id, {
            ...client.userGlobalSettings.get(req.user.id),
            verificationSubmit: true
        });
        try {
            client.emit("verificationSubmission", {
                userId: req.user.id,
                username: req.user.username,
                dob,
                fileBuffer: req.file.buffer
            });
        } catch (err) {
            res.redirect(`/?error=${encodeURIComponent(err.message)}`);
        }
    });

    app.post("/dashboard/settings/:guildID/test-welcome", ensureAuth, requireGuildSetup, async (req, res) => {
        const guildID = req.params.guildID;
        const guild = client.guilds.cache.get(guildID);
        const settings = client.settings.get(guildID);
        if (!guild) return res.send("Bot is not in this server.");
        // Create a fake member object
        const dummy = {
            id: "999999999999999999",
            username: "Test User",
            tag: "TestUser#0000",
        }
        const channel = guild.channels.cache.get(settings.welcomeChannel)
        const welcomeMessage = (settings.welcomeMessage || "Welcome {user} to {server}! You're member #{memberCount}.")
            .replace(/{user}/g, `<@${dummy.id}>`)
            .replace(/{server}/g, guild.name)
            .replace(/{memberCount}/g, guild.memberCount.toString());
        channel.send({ content: welcomeMessage }).catch(e => {
            res.redirect(`/?error=${encodeURIComponent(e.message)}`);
        });
        res.redirect(`/settings/${guildID}`);
    });

    app.post("/dashboard/settings/:guildID/test-leave", ensureAuth, requireGuildSetup, async (req, res) => {
        const guildID = req.params.guildID;
        const guild = client.guilds.cache.get(guildID);
        const settings = client.settings.get(guildID);
        const leaveChannel = settings.leaveChannel;
        if (!guild) return res.send("Bot is not in this server.");

        const dummyUser = {
            id: "999999999999999999",
            username: "TestUser",
            tag: "TestUser#0001"
        };

        // Emit the guildMemberRemove event
        const channel = guild.channels.cache.get(leaveChannel)
        const leaveMessage = (settings.leaveMessage || "{user} left {server}! #{memberCount}")
            .replace(/{user}/g, `<@${dummyUser.username}>`)
            .replace(/{server}/g, guild.name)
            .replace(/{memberCount}/g, guild.memberCount.toString());
        channel.send({ content: leaveMessage }).catch(e => {
            res.redirect(`/?error=${encodeURIComponent(e.message)}`);
        });

        res.redirect(`/settings/${guildID}`);
    });

    app.post("/dashboard/settings/:guildID/custom-commands/add", ensureAuth, requireGuildSetup, async (req, res) => {
        const guildID = req.params.guildID;
        const { name, response } = req.body;

        if (!name || !response) return res.redirect(`/settings/${guildID}`);
        const guildSettings = await client.settings.get(guildID);
        if (!guildSettings.customCommands) {
            guildSettings.customCommands = {};
        }
        guildSettings.customCommands[name] = response;
        await client.settings.set(guildID, guildSettings);

        res.redirect(`/dashboard/settings/${guildID}`);
    });

    // Delete a custom command
    app.post("/dashboard/settings/:guildID/custom-commands/delete", ensureAuth, requireGuildSetup, async (req, res) => {
        const guildID = req.params.guildID;
        const { name } = req.body;

        const guildSettings = await client.settings.ensure(guildID, { customCommands: {} });
        delete guildSettings.customCommands[name];
        await client.settings.set(guildID, guildSettings);

        res.redirect(`/dashboard/settings/${guildID}`);
    });

    app.get("/search/", ensureAuth, requireUserSetup, (req, res) => {
        const userId = req.query.id;
        if (!userId) {
            return res.render("user-search", {
                found: null,
                userId: null,
                user: req.user,
                userGlobal: null,
                favorites: [],
                sidebar: { active: "search", user: req.user },
                totalGuilds: client.guilds.cache.size,
                totalUsers: client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0)
            });
        }
        let favorites = songFavorites.get(userId);
        if (!Array.isArray(favorites)) favorites = [];
        const userGlobal = client.userGlobalSettings.get(userId);
    
        res.render("user-search", {
            found: !!userGlobal,
            userId,
            user: req.user,
            userGlobal,
            favorites,
            sidebar: {
                active: "search",
                user: req.user
            },
            totalGuilds: client.guilds.cache.size,
            totalUsers: client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0)
        });
    });

    // Save user settings (non-admins)
    app.post("/admin/reboot", ensureAuth, (req, res) => {
        if (!config.owners.includes(req.user.id)) return res.status(403).send("Forbidden");
        res.send("Rebooting bot...");
        setTimeout(() => {
            process.exit(0);
        }, 1000);
    });

    app.get("/dashboard/user/settings", ensureAuth, requireUserSetup, async(req, res) => {
        const userId = req.user.id;
        const userGuilds = req.user.guilds.filter(g => client.guilds.cache.has(g.id));
        const globalSettings = await client.userGlobalSettings.ensure(userId, {
            lang: "en",
            prefix: config.prefix,
            musicVolume: 50,
            musicRepeat: false,
            musicAutoplay: false,
            musicFilters: [],
            favoriteMovie: null,
            birthday: null,
            favoriteColor: null,
            favoriteFood: null,
            favoriteAnimal: null
        });
        const allFilters = Object.keys(client.distube.filters); // or however you get your DisTube filters

        res.render("user-settings", {
            user: req.user,
            sidebar: getSidebar(req.user, userGuilds, "global"),
            globalSettings,
            totalGuilds: client.guilds.cache.size,
            totalUsers: client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0),
            allFilters
        });
    });

    // Update user global settings
    app.post("/dashboard/user/settings/global", ensureAuth, (req, res) => {
        const userId = req.user.id;
        const musicRepeat = req.body.musicRepeat === "on"; // true if checked, false if not
        const musicFilters = Array.isArray(req.body.musicFilters) ? req.body.musicFilters : [];
        const musicAutoplay = req.body.musicAutoplay === "on"; // true if checked, false if not
        client.userGlobalSettings.set(userId, {
            ...client.userGlobalSettings.get(userId),
            ...req.body,
            musicRepeat,
            musicAutoplay,
            musicFilters: musicFilters.filter(f => f && client.distube.filters[f]) // Ensure valid filters
        });
        res.redirect("/dashboard/user/settings");
    });

    // Song Favorites tab
    app.get("/dashboard/user/favorites", ensureAuth, requireUserSetup, (req, res) => {
        const userId = req.user.id;
        const userGuilds = req.user.guilds.filter(g => client.guilds.cache.has(g.id));
        const favoritesRaw = client.songFavorites.get(userId);
        const favorites = Array.isArray(favoritesRaw) ? favoritesRaw : [];
        res.render("user-favorites", {
            user: req.user,
            sidebar: getSidebar(req.user, userGuilds, "favorites"),
            favorites,
            tab: "songs",
            totalGuilds: client.guilds.cache.size,
            totalUsers: client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0)
        });
    });

    // Delete selected song favorites
    app.post("/dashboard/user/favorites/delete", ensureAuth, (req, res) => {
        const userId = req.user.id;
        let favs = songFavorites.get(userId) || [];
        const toDelete = Array.isArray(req.body.selected) ? req.body.selected : [req.body.selected];
        favs = favs.filter(fav => !toDelete.includes(fav.url));
        songFavorites.set(userId, favs);
        res.redirect("/user-settings/favorites");
    });

    // Global Favorites tab (shows favorite fields from userGlobalSettings)

    // Per-Server Settings: show dropdown and user settings for selected server
    app.get("/dashboard/user/settings/server/", ensureAuth, requireUserSetup, async(req, res) => {
        const userId = req.user.id;
        const userGuilds = req.user.guilds.filter(g => client.guilds.cache.has(g.id));
        const selectedGuild = req.query.guild || (userGuilds[0] && userGuilds[0].id);
        let serverSettings = null;
        if (selectedGuild) {
            serverSettings = await client.userSettings.ensure(`${selectedGuild}_${userId}`, {
                lang: "en",
                notifications: true,
                interactions: true,
                
            });
        }
        res.render("user-server-settings", {
            user: req.user,
            sidebar: getSidebar(req.user, userGuilds, "server", selectedGuild),
            userGuilds,
            selectedGuild,
            serverSettings,
            totalGuilds: client.guilds.cache.size,
            totalUsers: client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0)
        });
    });

    // Update per-server user settings
    app.post("/dashboard/user/settings/server/", ensureAuth, (req, res) => {
        const userId = req.user.id;
        const guildID = req.body.guildID;
        client.userSettings.set(`${guildID}_${userId}`, {
            ...client.userSettings.get(`${guildID}_${userId}`),
            ...req.body
        });
        res.redirect(`/user-settings/server?guild=${guildID}`);
    });

    app.get("/setup/guild/:guildID", ensureAuth, async (req, res) => {
        const guildID = req.params.guildID;
        const guild = client.guilds.cache.get(guildID);
        if (!guild) return res.send("Bot is not in this server.");

        const channels = guild.channels.cache.filter(c => c.type === 0).map(c => ({ id: c.id, name: c.name }));
        const roles = guild.roles.cache.filter(r => r.name !== "@everyone").map(r => ({ id: r.id, name: r.name }));
        // Pass config.modules to the template for the modules dropdown
        res.render("guildsetup", { 
            user: req.user,
            guildID, 
            channels, 
            roles, 
            totalGuilds: client.guilds.cache.size,
            totalUsers: client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0),
            modules: Object.keys(config.modules) });
    });
    app.post("/setup/guild/:guildID", ensureAuth, async (req, res) => {
        const guildID = req.params.guildID;
        const { defaultRole, defaultMusicChannel, prefix, modules } = req.body;
        const welcomeChannel = req.body.welcomeChannel || null;
        const leaveChannel = req.body.leaveChannel || null;

        // Get the current module keys (from config or Enmap)
        const currentModules = Object.keys(config.modules);

        // Parse modules from comma-separated string to array
        let modulesArr = [];
        if (modules) {
            modulesArr = typeof modules === "string"
                ? modules.split(",").map(m => m.trim()).filter(Boolean)
                : modules;
        }

        // Build the modules object with booleans
        const modulesObj = {};
        for (const key of currentModules) {
            modulesObj[key] = modulesArr.includes(key); // returns true/false
        }

        // Await the set call to ensure data is stored before redirect
        await client.settings.set(guildID, {
            ...client.settings.get(guildID),
            welcomeChannel,
            leaveChannel,
            defaultRole,
            defaultMusicChannel,
            prefix,
            modules: modulesObj,
            setupComplete: true
        });

        res.redirect(`/dashboard/settings/${guildID}`);
    });
    app.get("/setup/user/:userId", ensureAuth, (req, res) => {
        if (req.user.id !== req.params.userId) return res.status(403).send("Forbidden");
        // Render a setup form
        res.render("setupUser", {
            user: req.user,
            totalGuilds: client.guilds.cache.size,
            totalUsers: client.guilds.cache.reduce((acc, g) => acc + g.memberCount, 0)
        });
    });

    app.post("/setup/user/:userId", ensureAuth, (req, res) => {
        if (req.user.id !== req.params.userId) return res.status(403).send("Forbidden");
        // Save global settings for the user
        client.userGlobalSettings.set(req.user.id, {
            lang: req.body.lang || "en",
            prefix: req.body.prefix || "n!",
            musicVolume: Number(req.body.musicVolume) || 50,
            favoriteMovie: req.body.favoriteMovie || null,
            birthday: req.body.birthday || null,
            favoriteColor: req.body.favoriteColor || null,
            favoriteFood: req.body.favoriteFood || null,
            favoriteAnimal: req.body.favoriteAnimal || null,
            setupComplete: true
        });
        res.redirect("/dashboard");
    });

    app.use(errorHandler)
    app.listen(3000, () => console.log("site running"));
    }catch(err) {
	require("./functions/errorListener").send(err)
	process.exit(0);
    }
}
startSite()
