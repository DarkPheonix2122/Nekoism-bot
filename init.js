const express = require("express");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const bodyParser = require("body-parser");
const path = require("path");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const axios = require("axios");
const multer = require("multer");
const { PORT, BOT_API, SHARED_SECRET, CLIENT_ID, CLIENT_SECRET, SESSION_SECRET } = process.env;

async function startSite() {
    require("./functions/errorListener")();
    const SITE_URL = "http://localhost:3000";
    const CALLBACK_SITE_URL = "http://localhost:3000/callback";
    const CALLBACK_LOGIN_URL = "http://localhost:3000/callback-verify";
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
    function getSidebar(user, guilds, active, selectedGuild) {
        return { user, guilds, active, selectedGuild };
    }
    function generateRandomPassword(length = 12) {
        return crypto.randomBytes(length).toString("base64").slice(0, length);
    }

    // --- ROUTES ---

    // Home
    app.get("/", async (req, res) => {
        let totalGuilds = 0, totalUsers = 0;
        try {
            const statsRes = await axios.get(`${BOT_API}/api/stats`, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
        } catch (e) {}
        res.render("index", { totalGuilds, totalUsers, user: req.user });
    });

    app.get("/about", (req, res) => { res.render("about", { user: req.user }); });

    app.get("/login", passport.authenticate("discord-login"));
    app.get("/callback", passport.authenticate("discord-login", { failureRedirect: "/" }), (req, res) => res.redirect("/dashboard"));
    app.get("/logout", (req, res) => { req.logout(() => res.redirect("/")); });

    // Dashboard: show all mutual servers, admin link if owner
    app.get("/dashboard", ensureAuth, async (req, res) => {
        let totalGuilds = 0, totalUsers = 0, isOwner = false, mutualGuilds = [];
        try {
            const [statsRes, ownersRes, guildsRes] = await Promise.all([
                axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/owners`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/guilds`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } })
            ]);
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
            isOwner = ownersRes.data.owners.includes(req.user.id);
            mutualGuilds = req.user.guilds.filter(g => guildsRes.data.some(bg => bg.id === g.id));
        } catch (e) {}
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
    app.get("/admin", ensureAuth, async (req, res) => {
        let totalGuilds = 0, totalUsers = 0, latency = 0, events = 0, commands = 0, isOwner = false;
        try {
            const [statsRes, ownersRes] = await Promise.all([
                axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/owners`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } })
            ]);
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
            isOwner = ownersRes.data.owners.includes(req.user.id);
            commands = statsRes.data.totalCommands || 0;
            events = statsRes.data.totalEvents || 0;
            latency = statsRes.data.totalLatency || 0;
        } catch (e) {}
        if (!isOwner) return res.status(403).send("Forbidden");
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

    // Guild Settings (view)
    app.get("/dashboard/settings/:guildID", ensureAuth, async (req, res) => {
        const guildID = req.params.guildID;
        let guild = {}, channels = [], roles = [], settingsData = {}, moduleKeys = [], isAdmin = false, mutualGuilds = [], totalGuilds = 0, totalUsers = 0;
        try {
            const [guildRes, settingsRes, statsRes, ownersRes, guildsRes] = await Promise.all([
                axios.get(`${BOT_API}/api/guilds/${guildID}`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/guild-settings/${guildID}`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/owners`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/guilds`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } })
            ]);
            guild = guildRes.data;
            channels = guild.channels;
            roles = guild.roles;
            settingsData = settingsRes.data;
            moduleKeys = Object.keys(settingsData.modules || {});
            mutualGuilds = req.user.guilds.filter(g => guildsRes.data.some(bg => bg.id === g.id));
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
            const userGuild = req.user.guilds.find(g => g.id === guildID);
            isAdmin = userGuild && (userGuild.permissions & 0x8) === 0x8;
        } catch (e) {}
        res.render("settings", {
            user: req.user,
            guildID,
            settings: settingsData,
            channels,
            roles,
            moduleKeys,
            isAdmin,
            sidebar: getSidebar(req.user, mutualGuilds, "settings"),
            totalGuilds,
            totalUsers
        });
    });

    // Save guild settings (admin only)
    app.post("/dashboard/settings/:guildID", ensureAuth, async (req, res) => {
        const guildID = req.params.guildID;
        const userGuild = req.user.guilds.find(g => g.id === guildID);
        const isAdmin = userGuild && (userGuild.permissions & 0x8) === 0x8;
        if (!isAdmin) return res.status(403).send("Forbidden");

        // Prepare modules object
        let { modules } = req.body;
        const modulesArr = Array.isArray(modules) ? modules : (modules ? [modules] : []);
        let modulesObj = {};
        try {
            const configRes = await axios.get(`${BOT_API}/api/guild-settings/${guildID}`, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
            const currentModules = Object.keys(configRes.data.modules || {});
            for (const key of currentModules) {
                modulesObj[key] = modulesArr.includes(key);
            }
        } catch (e) {}

        // Send update to API
        try {
            await axios.post(`${BOT_API}/api/guild-settings/${guildID}`, {
                ...req.body,
                modules: modulesObj
            }, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {}
        res.redirect(`/dashboard/settings/${guildID}`);
    });

    // User global settings (view)
    app.get("/dashboard/user/settings", ensureAuth, async (req, res) => {
        let globalSettings = {};
        let totalGuilds = 0, totalUsers = 0, allFilters = [];
        try {
            const [userRes, statsRes, filtersRes] = await Promise.all([
                axios.get(`${BOT_API}/api/user-global/${req.user.id}`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/filters`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }).catch(() => ({ data: { filters: [] } }))
            ]);
            globalSettings = userRes.data;
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
            allFilters = filtersRes.data.filters || [];
        } catch (e) {}
        res.render("user-settings", {
            user: req.user,
            sidebar: getSidebar(req.user, req.user.guilds, "global"),
            globalSettings,
            totalGuilds,
            totalUsers,
            allFilters
        });
    });

    // Update user global settings
    app.post("/dashboard/user/settings/global", ensureAuth, async (req, res) => {
        try {
            await axios.post(`${BOT_API}/api/user-global/${req.user.id}`, req.body, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {}
        res.redirect("/dashboard/user/settings");
    });

    // Song Favorites tab
    app.get("/dashboard/user/favorites", ensureAuth, async (req, res) => {
        let favorites = [];
        let totalGuilds = 0, totalUsers = 0;
        try {
            const [favRes, statsRes] = await Promise.all([
                axios.get(`${BOT_API}/api/song-favorites/${req.user.id}`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } })
            ]);
            favorites = favRes.data;
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
        } catch (e) {}
        res.render("user-favorites", {
            user: req.user,
            sidebar: getSidebar(req.user, req.user.guilds, "favorites"),
            favorites,
            tab: "songs",
            totalGuilds,
            totalUsers
        });
    });

    // Update song favorites
    app.post("/dashboard/user/favorites", ensureAuth, async (req, res) => {
        try {
            await axios.post(`${BOT_API}/api/song-favorites/${req.user.id}`, { favorites: req.body.favorites }, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {}
        res.redirect("/dashboard/user/favorites");
    });

    // Per-Server User Settings
    app.get("/dashboard/user/settings/server/", ensureAuth, async (req, res) => {
        const userId = req.user.id;
        const selectedGuild = req.query.guild || (req.user.guilds[0] && req.user.guilds[0].id);
        let serverSettings = null, totalGuilds = 0, totalUsers = 0;
        try {
            if (selectedGuild) {
                const [settingsRes, statsRes] = await Promise.all([
                    axios.get(`${BOT_API}/api/user-settings/${selectedGuild}/${userId}`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                    axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } })
                ]);
                serverSettings = settingsRes.data;
                totalGuilds = statsRes.data.totalGuilds;
                totalUsers = statsRes.data.totalUsers;
            }
        } catch (e) {}
        res.render("user-server-settings", {
            user: req.user,
            sidebar: getSidebar(req.user, req.user.guilds, "server", selectedGuild),
            userGuilds: req.user.guilds,
            selectedGuild,
            serverSettings,
            totalGuilds,
            totalUsers
        });
    });

    // Update per-server user settings
    app.post("/dashboard/user/settings/server/", ensureAuth, async (req, res) => {
        const userId = req.user.id;
        const guildID = req.body.guildID;
        try {
            await axios.post(`${BOT_API}/api/user-settings/${guildID}/${userId}`, req.body, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {}
        res.redirect(`/dashboard/user/settings/server?guild=${guildID}`);
    });

    // Setup routes (guild/user)
    app.get("/setup/guild/:guildID", ensureAuth, async (req, res) => {
        const guildID = req.params.guildID;
        let guild = {}, channels = [], roles = [], totalGuilds = 0, totalUsers = 0, modules = [];
        try {
            const [guildRes, statsRes, settingsRes] = await Promise.all([
                axios.get(`${BOT_API}/api/guilds/${guildID}`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/guild-settings/${guildID}`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } })
            ]);
            guild = guildRes.data;
            channels = guild.channels;
            roles = guild.roles;
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
            modules = Object.keys(settingsRes.data.modules || {});
        } catch (e) {}
        res.render("guildsetup", {
            user: req.user,
            guildID,
            channels,
            roles,
            totalGuilds,
            totalUsers,
            modules
        });
    });

    app.post("/setup/guild/:guildID", ensureAuth, async (req, res) => {
        const guildID = req.params.guildID;
        let modulesArr = [];
        if (req.body.modules) {
            modulesArr = Array.isArray(req.body.modules) ? req.body.modules : [req.body.modules];
        }
        let modulesObj = {};
        try {
            const configRes = await axios.get(`${BOT_API}/api/guild-settings/${guildID}`, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
            const currentModules = Object.keys(configRes.data.modules || {});
            for (const key of currentModules) {
                modulesObj[key] = modulesArr.includes(key);
            }
        } catch (e) {}
        try {
            await axios.post(`${BOT_API}/api/guild-settings/${guildID}`, {
                ...req.body,
                modules: modulesObj,
                setupComplete: true
            }, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {}
        res.redirect(`/dashboard/settings/${guildID}`);
    });

    app.get("/setup/user/:userId", ensureAuth, async (req, res) => {
        if (req.user.id !== req.params.userId) return res.status(403).send("Forbidden");
        let totalGuilds = 0, totalUsers = 0;
        try {
            const statsRes = await axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } });
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
        } catch (e) {}
        res.render("setupUser", {
            user: req.user,
            totalGuilds,
            totalUsers
        });
    });

    app.post("/setup/user/:userId", ensureAuth, async (req, res) => {
        if (req.user.id !== req.params.userId) return res.status(403).send("Forbidden");
        try {
            await axios.post(`${BOT_API}/api/user-global/${req.user.id}`, {
                ...req.body,
                setupComplete: true
            }, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {}
        res.redirect("/dashboard");
    });

    // Song favorites delete (example)
    app.post("/dashboard/user/favorites/delete", ensureAuth, async (req, res) => {
        try {
            await axios.post(`${BOT_API}/api/song-favorites/${req.user.id}`, { favorites: req.body.favorites || [] }, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {}
        res.redirect("/dashboard/user/favorites");
    });

    // Error handler
    app.use(errorHandler);

    app.listen(PORT, () => console.log("site running"));
}
startSite();
