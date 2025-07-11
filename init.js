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
let debug = false
const { SITE_URL, PORT, BOT_API, SHARED_SECRET, CLIENT_ID, CLIENT_SECRET, SESSION_SECRET } = process.env;
async function startSite() {
    require("./functions/errorListener")();
    const CALLBACK_SITE_URL = `${SITE_URL}callback`;
    const CALLBACK_LOGIN_URL = `${SITE_URL}callback-verify`;
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
    app.use((req, res, next) => {
    const ignorePaths = ["/login", "/callback", "/login-verify", "/callback-verify"];

    if (
        req.method === "GET" &&
        !ignorePaths.includes(req.path) &&
        (req.path === "/" || req.path.startsWith("/dashboard"))
    ) {
        res.cookie("returnTo", req.originalUrl, { maxAge: 5 * 60 * 1000 });
    }

    next();
    });

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
        let error = req.query.error
        if(error){
            return require("./functions/errorHandler")(error, req, res)
        }
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
    app.get("/login-verify", passport.authenticate("discord-verify"));
    app.get("/debug", (req, res, next) => {
        const debugState = req.query.debug;
        if(debugState === null) return res.send("no params...");
        debug = debugState;
        res.redirect("/")
    })
    app.get("/callback", (req, res, next) => {
        try{
            passport.authenticate("discord-login", { failureRedirect: "/" }, (req, res) => {
                const redirectTo = req.cookies?.returnTo|| "/dashboard";
                return res.redirect(redirectTo);
            })(req, res, next);
    }catch(err){
        require("./functions/errorListener").send(err?.message)
    }
    });
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }

        // Send update to API
        try {
            await axios.post(`${BOT_API}/api/guild-settings/${guildID}`, {
                ...req.body,
                modules: modulesObj
            }, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
            favorites = Array.isArray(favRes.data) ? favRes.data : [];
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
    // ...existing code...

    const multer = require("multer");
    const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB max


    // Verification page
    app.get("/verification", ensureAuth, async (req, res) => {
        let totalGuilds = 0, totalUsers = 0;
        try {
            const [userRes, statsRes] = await Promise.all([
                axios.get(`${BOT_API}/api/user-global/${req.user.id}`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } }),
                axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } })
            ]);

            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
        res.render("verification", {
            user: req.user,
            userGlobalSettings: userRes,
            totalGuilds,
            totalUsers,
            sidebar: getSidebar(req.user, req.user.guilds, "verification")
        });
    });

    // Verification form POST
    app.post("/verification", ensureAuth, upload.single("photo"), async (req, res) => {
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

        // Save verification status (replace with DB in production)
        try {
            await axios.post(`${BOT_API}/api/user-global/${req.user.id}`, req.body, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {
            require("./functions/errorListener").send(e)
        }

        // You can emit an event, log, or handle as needed here
        // For demo, just redirect
        res.redirect("/verification?success=1");
    });
    // ...existing code...

    // Update per-server user settings
    app.post("/dashboard/user/settings/server/", ensureAuth, async (req, res) => {
        const userId = req.user.id;
        const guildID = req.body.guildID;
        try {
            await axios.post(`${BOT_API}/api/user-settings/${guildID}/${userId}`, req.body, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
        try {
            await axios.post(`${BOT_API}/api/guild-settings/${guildID}`, {
                ...req.body,
                modules: modulesObj,
                setupComplete: true
            }, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
        res.redirect(`/dashboard/settings/${guildID}`);
    });

    app.get("/setup/user/:userId", ensureAuth, async (req, res) => {
        if (req.user.id !== req.params.userId) return res.status(403).send("Forbidden");
        let totalGuilds = 0, totalUsers = 0;
        try {
            const statsRes = await axios.get(`${BOT_API}/api/stats`, { headers: { Authorization: `Bearer ${SHARED_SECRET}` } });
            totalGuilds = statsRes.data.totalGuilds;
            totalUsers = statsRes.data.totalUsers;
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
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
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
        res.redirect("/dashboard");
    });

    // Song favorites delete (example)
    app.post("/dashboard/user/favorites/delete", ensureAuth, async (req, res) => {
        try {
            await axios.post(`${BOT_API}/api/song-favorites/${req.user.id}`, { favorites: req.body.favorites || [] }, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
        } catch (e) {
            require("./functions/errorListener").send(e)
        }
        res.redirect("/dashboard/user/favorites");
    });
    app.get("/callback-verify", (req, res, next) => {
        passport.authenticate("discord-verify", async (err, user, info) => {
            if (err || !user) {
                return res.redirect("/?error=" + encodeURIComponent(err?.message || "No user returned"));
            }


                const guildID = req.cookies.guildID;
                if (!guildID) {
                    return res.redirect("/?error=" + encodeURIComponent("Missing guildID in session"));
                }

                const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
                const userID = req.user.id;

                try {
                    // 1. Check if this IP was already used by a different user in this guild
                    const altRes = await axios.get(`${BOT_API}/api/altDetection/${guildID}/${ip}`, {
                        headers: { Authorization: `Bearer ${SHARED_SECRET}` }
                    });

                    const isAlt = altRes.data.alt && altRes.data.userId !== userID;

                    // 2. Check if account is too new
                    const creationDate = new Date(userID / 4194304 + 1420070400000);
                    const ageInDays = Math.floor((Date.now() - creationDate) / (1000 * 60 * 60 * 24));
                    const isTooNew = ageInDays < 10;

                    if (isAlt) {
                        return res.redirect("/alt-warning?reason=ip-linked&user=" + altRes.data.userId);
                    }

                    if (isTooNew) {
                        return res.redirect("/alt-warning?reason=new-account&days=" + ageInDays);
                    }

                    // 3. Register IP if not alt
                    await axios.post(`${BOT_API}/api/altDetection/${guildID}/${ip}/${userID}`, {}, {
                        headers: { Authorization: `Bearer ${SHARED_SECRET}` }
                    });

                    // Proceed to verification
                    res.redirect(`/verify/${guildID}`);
                } catch (e) {
                    console.error("Alt detection failed:", e.message);
                    return res.redirect("/?error=" + encodeURIComponent("Alt detection failed."));
                }
        })(req, res, next);
    });

    app.get("/verify/:guildID", ensureAuth, async (req, res) => {
        const guildID = req.params.guildID;
        const userID = req.user.id;
        const password = generateRandomPassword();

        try {
            // 1. Fetch or create user global settings
            let userGSettings = {};
            try {
                const gRes = await axios.get(`${BOT_API}/api/user-global/${userID}`, {
                    headers: { Authorization: `Bearer ${SHARED_SECRET}` }
                });
                userGSettings = gRes.data || {};
            } catch {
                userGSettings = {};
            }

            // 2. Store password if not set
            if (!userGSettings.password) {
                userGSettings.password = password;
                await axios.post(`${BOT_API}/api/user-global/${userID}`, userGSettings, {
                    headers: { Authorization: `Bearer ${SHARED_SECRET}` }
                });
            }

            // 3. Calculate account age
            const creationDate = new Date(userID / 4194304 + 1420070400000);
            const ageInDays = Math.floor((Date.now() - creationDate) / (1000 * 60 * 60 * 24));
            const showPassword = ageInDays >= 10;

            // 4. Get guild info and role name
            const guildRes = await axios.get(`${BOT_API}/api/guilds/${guildID}`, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });
            const settingsRes = await axios.get(`${BOT_API}/api/guild-settings/${guildID}`, {
                headers: { Authorization: `Bearer ${SHARED_SECRET}` }
            });

            const guildName = guildRes.data.name || "your server";
            const roleId = settingsRes.data.verifiedRole;
            const role = guildRes.data.roles.find(r => r.id === roleId);
            const roleName = role?.name || "Verified";

            res.clearCookie("guildID");

            res.send(`
                <h2>Verification for ${guildName}</h2>
                <p>Your account is ${ageInDays} days old.</p>
                ${showPassword 
                    ? `<p>🔐 Your password: <code>${userGSettings.password}</code>. Use it with <code>!verify ${userGSettings.password}</code> in DMs to get the role "<strong>${roleName}</strong>".</p>
                    <p>If the bot doesn't respond, use <code>!verify dm</code> in the server to unlock DMs.</p>`
                    : `<p>❌ Your account is too new to verify. Try again in ${10 - ageInDays} days.</p>`}
            `);

            req.logout(() => {});
        } catch (e) {
            console.error("Verify route error:", e.message);
            res.redirect(`/?error=${encodeURIComponent("Verification error: " + e.message)}`);
        }
    });

    app.get("/alt-warning", (req, res) => {
        const reason = req.query.reason;
        const days = req.query.days;
        const user = req.query.user;

        let message = "Access denied due to suspicious activity.";

        if (reason === "ip-linked") {
            message = `❌ This IP address is already linked to user ID: ${user}.`;
        } else if (reason === "new-account") {
            message = `⏳ Your account is only ${days} days old. You must wait until it is at least 10 days old to verify.`;
        }

        res.send(`<h2>Alt Detection Blocked</h2><p>${message}</p>`);
    });




    // Error handler
    app.use(errorHandler);

    app.listen(PORT, () => console.log("site running at "+ SITE_URL));
}
startSite();
